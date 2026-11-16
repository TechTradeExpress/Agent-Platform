# ADR 009: provider authentication terms and harness isolation gates

**Contract:** AP-HAUTH/1. **Status:** PROPOSED / DESIGN_ONLY / OFFLINE_ONLY /
SOURCE_ONLY / HOST_NOT_RUN. **Issue:** [HAR-05 #135](https://github.com/TechTradeExpress/Agent-Platform/issues/135),
within [HAR-00 #130](https://github.com/TechTradeExpress/Agent-Platform/issues/130).
**Stacked base:** published HAR-04 head `c0064fa7e54824d3cedd98037154fececfd2073c`
(tree `13d250275ce7811f46c55fea8701c855e88f9b3f`, Draft PR #144, `CI` and
`Debian package` SUCCESS). Delivery of this change is local-only.

This ADR is a decision record, not an authentication or launch mechanism. It adds
no login, token handling, credential proxy, launcher, SDK use, API-billed fallback,
host change or provider request. It extends [ADR 003](subscription-transport.md),
[ADR 004](architecture-trust-boundaries.md), [ADR 005](native-runtime-feasibility.md)
and [ADR 008](multi-harness-architecture.md) and **narrows** them: nothing here
loosens a prior gate.

Unchanged and binding: `SUBSCRIPTION_ISOLATION_BLOCKED` / public exit 13,
`LIVE_NO_GO`, `HOST_NOT_RUN`, Gate #73 BLOCKED, native `run`/`resume` BLOCKED, one
operator-selected harness per worker, one root `AGENTS.md`, independent GitHub App
Publisher/Signer, independent review and **human-only merge**.

## Context and assumptions

| # | Assumption (fact, assumption or recommendation is stated per line) |
| --- | --- |
| C1 | **Fact (Issue #135, maintainer 2026-11-16):** the target is a private, single-user, self-hosted homelab using the maintainer's own first-party Codex and Claude Code subscriptions. Not resale, not third-party users, not a hosted commercial service, not a Claude proxy. |
| C2 | **Fact (same clarification):** this is a scoping correction, not authorization for product-controlled execution. |
| C3 | **Decision:** private ownership of the host does **not** by itself approve automated use of consumer OAuth. A private homelab is neither presumed commercial nor presumed permitted. |
| C4 | **Decision:** a successful interactive login proves only that the vendor's own flow worked. It is not evidence that Agent Platform may run tasks with that login. |
| C5 | **Assumption:** vendor documentation may change without notice; every conclusion below is dated and must be re-observed (see "Freshness"). |
| C6 | **Decision:** this ADR is the project's engineering interpretation. It is **not** legal advice and **not** a vendor approval. No row below may be cited as a grant from Anthropic or OpenAI. |

## Official sources and our interpretation

Observed **2026-11-16** by plain documentation page fetches (text read as data; no
CLI, login, `auth status`, token inspection or API request was made). Pages are
mutable; the exact bytes are not pinned here. Quotes are short excerpts; the
"Interpretation" column is ours.

| ID | Source | What the document says (excerpt) | Interpretation / uncertainty |
| --- | --- | --- | --- |
| S1 | [Claude legal and compliance](https://code.claude.com/docs/en/legal-and-compliance) | "OAuth authentication is intended exclusively for purchasers of Claude Free, Pro, Max, Ultra, Team, and Enterprise subscription plans and is designed to support ordinary use of Claude Code and other native Anthropic applications." | Supports row 2. "Ordinary use" is undefined; where unattended orchestration begins is **not defined**. |
| S1 | same | "Developers building products or services that interact with Claude's capabilities, including those using the Agent SDK, should use API key authentication … Anthropic does not permit third-party developers to offer Claude.ai login into their own applications, or to route requests through Free, Pro, Max, or Ultra plan credentials on behalf of their users. Moreover, developers may not collect, store, or intermediate Claude.ai credentials or session tokens." | Blocks rows 7 and (for any design that stores/forwards tokens) 5/6. Whether a single-owner private orchestrator is a "product or service" is **unresolved (NOT_PROVEN)**; the text addresses "on behalf of their users", which does not describe the owner acting for themselves, but it does not exempt them either. |
| S1 | same | "Nor does it prevent an end user from signing in to the unmodified Claude Code binary with their own Claude subscription, including where a platform hosts Claude Code …" | Supports rows 2 and 3, including on a VM, provided the human signs in through the vendor's flow with their own account. |
| S1 | same | "Advertised usage limits for Pro, Max, and Ultra plans assume ordinary, individual usage of Claude Code and the Agent SDK." | Ambiguous: it names the Agent SDK next to individual use without saying scripted use is covered. Not usable as a grant. |
| S1 | same | "preinstalling or running Claude Code in your products or services (e.g. in hosted sandboxes or other agent infrastructure) requires agreeing to our Commercial Terms of Service" and the binary "must not be modified … customers may not remove, disable, or restrict any authentication method built into it". | Applies to products offered to others (row 9, out of scope). Whether a private orchestrator is "agent infrastructure" is **NOT_PROVEN**. Our design must never modify/wrap the auth path regardless. |
| S2 | [Programmatic mode](https://code.claude.com/docs/en/headless) | "This page covers using the Agent SDK via the CLI (`claude -p`)." `--bare`: "Claude Code never reads OAuth credentials or the system keychain"; needs `ANTHROPIC_API_KEY` or `apiKeyHelper`. Without `--bare`, "a `-p` session shows no workspace trust dialog and no per-server approval prompt" and runs project hooks and `.mcp.json` servers. | `claude -p` is documented as the Agent SDK path, so row 4 inherits the S1 uncertainty. `--bare` is an API-key mode and is **never** a subscription workaround (and is not adopted as a default). `-p` skips trust prompts, which is a security input, not a licence input. |
| S3 | [CLI reference](https://code.claude.com/docs/en/cli-reference) | `claude setup-token`: "Generate a long-lived OAuth token for CI and scripts. Prints the token to the terminal without saving it. Requires a Claude subscription." `--dangerously-skip-permissions`: "Skip permission prompts." `--resume`: searches the current project "then every other project on this machine". `--no-session-persistence`: print mode only. | The vendor documents a token for scripts, which is a documentation fact but not a statement that Agent Platform may handle that token (S1 forbids intermediation). We never generate, print, store or forward it. Resume-by-ID is machine-wide, so a session ID is not a scoped capability. |
| S4 | [Settings](https://code.claude.com/docs/en/settings) | Precedence: managed, command line (`--settings`), project local, shared project, user. "In a worktree, it uses the file at the main checkout's root" for `.claude/settings.local.json`. `permissions.defaultMode` `auto`/`bypassPermissions` "don't take effect from project or local settings". `CLAUDE_CONFIG_DIR` relocates settings, session history and plugins. | Settings are layered and partly writable by the session itself; a worktree does **not** isolate the local settings file. Repository files are untrusted input. |
| S5 | [Memory](https://code.claude.com/docs/en/memory) | "Claude treats them as context, not enforced configuration. To block an action regardless of what Claude decides, use a PreToolUse hook instead." `AGENTS.md` is read only when no `CLAUDE.md`/`CLAUDE.local.md` exists in the working directory or above (Claude Code 2.1.277+). | Confirms `AGENTS.md` is not a security boundary. A competing `CLAUDE.md` silently replaces it (already handled by HAR-04 `instruction_sources`). |
| S6 | [Claude authentication](https://code.claude.com/docs/en/authentication) (supplementary, not in the Issue list) | Linux credentials in `~/.claude/.credentials.json` mode 0600 (under `CLAUDE_CONFIG_DIR` if set). Precedence: cloud provider, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY` ("In non-interactive mode (`-p`), the key is always used when present"), `apiKeyHelper`, `CLAUDE_CODE_OAUTH_TOKEN`, profiles, then subscription login. | An ambient API key silently outranks the subscription: **surprise API billing** is a real failure mode. Credentials are plain files readable by the same UID. |
| S7 | [OpenAI authentication](https://learn.chatgpt.com/docs/auth) (`developers.openai.com/codex/auth` redirects here) | "Sign in with ChatGPT for subscription access" / "Sign in with an API key for usage-based access"; cache in `~/.codex/auth.json` (plaintext) or keyring, "treat `~/.codex/auth.json` like a password"; "Use API key authentication for programmatic Codex CLI workflows, such as CI/CD jobs"; "Don't expose Codex execution in untrusted or public environments"; "Access tokens are intended for trusted scripts, schedulers, and private CI runners." | Supports row 1. For automation the vendor recommends an API key; ChatGPT-token automation is an "advanced" path (S8). Billing differs by method. |
| S8 | [OpenAI CI/CD auth](https://learn.chatgpt.com/docs/auth/ci-cd-auth) | "The right way to authenticate automation is with an API key." ChatGPT-managed auth in CI is "an advanced workflow for enterprise and other trusted private automation"; "Use one `auth.json` per runner"; "Do not share the same file across concurrent jobs or multiple machines"; "Do not use this workflow for public or open-source repositories." | Row 4 (Codex) and row 5 are **NOT_PROVEN/BLOCKED**: the vendor path for ChatGPT auth in automation requires persisting a refreshed `auth.json`, i.e. the credential custody we forbid, and this repository is public. |
| S9 | [ADR 003](subscription-transport.md) (project record, 2026-10-28) | SIWC token-sharing flows and Codex app-server token delivery were reviewed; eligibility "UNVERIFIED"; no transfer, no OAuth through our broker. | Unchanged. This ADR does not revive SIWC, app-server token handoff or custom Responses transport. |

**Uncertainty bounds.** (1) Only documentation pages above were read; the
underlying Consumer/Commercial Terms of Service and Usage Policy texts were **not**
analyzed, and OpenAI's terms of service were not read. (2) WebFetch summarization
may omit passages; quotes were checked against returned text but pages were not
archived byte-for-byte. (3) Nothing was observed about enforcement behaviour,
quota accounting for scripted use, or how a vendor classifies a private
orchestrator. (4) No vendor contact was made. Any row marked SUPPORTED means
"documented as the vendor's ordinary path", not "approved for this project".

## Decision matrix

Each row has **three independent decisions** (see next section): **A** vendor
permission, **B** isolation/process safety, **C** operator approval for a specific
worker. `n/a` means the decision does not apply because **no Agent Platform
component launches, supervises or relays the provider process**; it is not a PASS,
proves nothing about isolation and never carries over to another row. `Overall` is
SUPPORTED only if A is SUPPORTED and every other decision is `n/a` or itself
satisfied; any `NOT_PROVEN`, `NOT_RUN` or `BLOCKED` cell prevents SUPPORTED. No row
may derive one decision from another. Status values: `SUPPORTED`, `NOT_PROVEN`,
`BLOCKED`, `OUT_OF_SCOPE`.

| # | Scenario | A | B | C | Overall | Evidence and rationale | Proof gate before any change |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Personal, interactive **Codex CLI**, operator's own ChatGPT subscription, human at the terminal | SUPPORTED | n/a (no Agent Platform process involved) | n/a | **SUPPORTED** | S7: ChatGPT sign-in is the documented default. Interactive login is performed by the human through the vendor flow only. | None for use. Recheck S7 when the CLI pin changes. Does not extend to `codex exec` driven by us (row 4/5). |
| 2 | Personal, interactive **Claude Code**, operator's own subscription, human at the terminal | SUPPORTED | n/a | n/a | **SUPPORTED** | S1: end user signing in to the unmodified binary with their own subscription is expressly not restricted. | None for use. The binary must be unmodified and run as published (HAR-04 pins an official artifact; not wrapped). |
| 3 | Supervised development on a worker (AGENTS.md section 1): human assigns one Issue, sits in an interactive session on their own login, worktree per Issue | SUPPORTED | n/a (no Agent Platform process launches or supervises the provider CLI; the human does) | n/a (authority is the human's direct instruction, not an Agent Platform approval) | **SUPPORTED as supervised development only** | S1 "including where a platform hosts Claude Code"; S7. Rests on the human performing login on that host personally, no copied credentials, no unattended continuation. Authority is the human's direct instruction ([AGENTS.md](../AGENTS.md)); it **never transfers** to the product runtime. This row says nothing about isolation: the worker is a normal Unix user and session files are readable by that UID, so Agent Platform isolation on that worker remains NOT_PROVEN and is decided only under rows 5, 6 and 10. | Conditions: attended, interactive, own account, no `-p`, no background sessions left running, no `--dangerously-skip-permissions`, credentials stay in the vendor-owned home, nothing from this session feeds Agent Platform. Violating any condition moves the case to row 4/5. |
| 4 | Operator-started scripted CLI: `claude -p` / `codex exec`, one-shot, operator watching, own account | NOT_PROVEN | NOT_RUN | NOT_RUN | **NOT_PROVEN** | S2: `claude -p` is "the Agent SDK via the CLI". S1 steers SDK/product use to API keys but also mentions the Agent SDK under individual plan limits. S3 documents `setup-token` for scripts. S7/S8: OpenAI recommends API keys for programmatic Codex. Documentation is internally unclear; it is not a grant. | Written vendor clarification (draft questions below) **or** operator's explicit decision to use an API-billed credential under row 8. Until then do not script a provider CLI, even by hand, on the project's behalf. |
| 5 | **Agent Platform** starts, supervises and finishes provider tasks without a human in the session (unattended orchestration) | NOT_PROVEN | BLOCKED | NOT_RUN | **BLOCKED** | S1: "agent infrastructure"/"products or services" boundary unclear for a private orchestrator; S7/S8: vendor path needs credential custody. B is BLOCKED by existing gates: `SUBSCRIPTION_ISOLATION_BLOCKED`, ADR 005 and AP-NS/1 (no complete tool/credential boundary, no VERIFIED_MEDIATED route), Gate #73. Private ownership does not cure this (C3). | A, B and C all independently resolved (next section) plus HAR-07 and Gate #73. Absence of any evidence is not GO. |
| 6 | Control Plane **resumes** sessions, handles tool calls or executes commands automatically on behalf of a provider session | NOT_PROVEN | BLOCKED | NOT_RUN | **BLOCKED** | Subset of row 5 with additional hazards: session IDs resolve machine-wide (S3), tool effects may be UNKNOWN after a kill (S2 SIGTERM leaves a turn unfinished), replay and cross-harness continuation. ADR 008 forbids latest/fork/cross-harness resume. | Row 5 gates plus exact checkpoint binding (ADR 008), reconciled UNKNOWN effects and process-tree death proof. |
| 7 | Agent SDK embedding, OAuth intermediation, token generation/storage/refresh by Agent Platform, `setup-token` handling, "Sign in with" relay, any use of one login to authenticate another | BLOCKED | BLOCKED | NOT_RUN | **BLOCKED** | S1: developers "may not collect, store, or intermediate Claude.ai credentials or session tokens"; SDK users "should use API key authentication". S7/S8: no custody of `auth.json`. S9: SIWC/token transfer not authorized. | None. Do not design toward this. Only a new maintainer decision plus vendor commercial agreement could reopen it, and it would be a different ADR. |
| 8 | Separate **API-billed** credential (Anthropic Console key / OpenAI Platform key) for automation | NOT_PROVEN (commercial terms apply; not reviewed) | BLOCKED (no secret-delivery boundary designed) | NOT_RUN | **BLOCKED** | S2/S6/S7/S8 recommend API keys for automation, so this is the vendor-aligned direction, but it changes billing. Buying a subscription is not authorization to incur API charges, and an ambient `ANTHROPIC_API_KEY` silently overrides the subscription (S6). Issue #135 requires independent opt-in and billing approval. | A new ADR with: explicit operator billing opt-in and spending cap, separate account/key ownership, key delivery design that is not env/argv/file readable by tools, and a proof that no subscription credential is present or used. Never an automatic fallback on quota or error. |
| 9 | Hosting the tool for other users, multi-user, commercial offering | OUT_OF_SCOPE | OUT_OF_SCOPE | OUT_OF_SCOPE | **OUT_OF_SCOPE** | Issue #135 scope; S1 requires Commercial Terms and end-user authentication for such products. | Out of project scope; no design work. |
| 10 | Codex login state, Claude login state and the worker's GitHub App Publisher/Signer credentials **coexisting** on one host or worker | n/a | NOT_PROVEN | NOT_RUN | **NOT_PROVEN** | Distinct custodians are required by ADR 008 (one harness per worker) and the Publisher contract. No kernel/FD/proc/env evidence exists (AP-NS/1 NO-GO). Provider authentication never implies task authorization or GitHub authority. | Evidence classes E-ISO-1..9 below, separately for each pair. |

Reading rule: an Overall of **SUPPORTED** (rows 1-3) means only that the vendor
documents the operator's own attended, interactive use. It does **not** establish
Agent Platform isolation, process safety or operator approval of any product
execution, and it is not a precedent for any other row. B and C are `n/a` in rows
1-3 because Agent Platform is not in the loop; they become mandatory the moment it
is (rows 4-8), and then `n/a` is not allowed.

## Three independent decisions

| Decision | Question | Who may decide | Evidence | Fails closed to |
| --- | --- | --- | --- | --- |
| **A. Vendor permission** | Does the provider permit this exact usage pattern for this account type? | Maintainer, after reading current official terms **and**, where ambiguous, written vendor clarification | S1-S8 style dated source digests; clarification reference | `NOT_PROVEN` |
| **B. Isolation and process safety** | Is credential custody, tool mediation, session, config and output handling proven for this exact binary, host and configuration? | Independent reviewer on reproducible, secret-free evidence (HAR-07 and Gate #73) | E-ISO classes, negative-test results | `NOT_RUN` / `BLOCKED` |
| **C. Operator approval** | Has the actual operator approved this harness on this worker, at this epoch, for this scope, until this time? | The human operator, external to the JSON bytes | Approval bound to worker, enrollment, `selection_epoch`, harness, ADR/config digests, expiry | `NOT_RUN` |

Rules:

1. All three must be independently resolved before any future production harness
   invocation. A satisfied A does not imply B or C; B does not imply A; C never
   overrides A or B. No decision can be inferred from installation, inventory,
   login success, a doctor result, CI PASS, a mocked success or a prior approval of
   another worker/harness/epoch.
2. Missing, expired, stale, mismatched or unparseable evidence yields `NOT_PROVEN`,
   `NOT_RUN` or `BLOCKED`, **never** a default GO. This revision defines **no GO
   state**: the closed [evidence schema](harness-auth-evidence.schema.json) fixes
   `launch_allowed=false` and `production_go=false`. A later ADR must introduce any
   positive state.
3. These decisions are **independent of GitHub publication**: provider
   authentication is never GitHub authority. The per-worker GitHub App, Signer,
   independent review and human-only merge are unaffected and cannot be satisfied
   by, or substituted for, A/B/C. A different harness is not an independent reviewer.
4. A is re-decided when the CLI version pin, the account/plan type, the usage
   pattern or the vendor documents change. B is re-decided when the binary,
   configuration, kernel profile or tool set changes. C expires with the epoch.

## Authentication, session and configuration separation

Requirements for any future design (none implemented here):

- **Vendor-owned login only.** Login is performed by the human through the
  vendor's own interactive flow in the harness's own configuration home. Agent
  Platform never collects, serializes, mirrors, scans, copies, backs up, proxies,
  refreshes or logs tokens or cookies; never reads `auth.json`, `.credentials.json`,
  keyrings or `~/.claude.json`; has no key fallback; never uses one account to sign
  into another; and produces no secret-bearing diagnostics.
- **Distinct homes.** Codex state lives only under its own `CODEX_HOME`; Claude
  state only under its own `CLAUDE_CONFIG_DIR` (S4/S6). Homes are per worker, per
  harness, owned by the coding identity, never a shared path, never another user's
  home, never reachable from the other harness's tool domain. Existing `~/.codex`
  and `~/.claude` of the operator are never read or reused by a product path.
- **No ambient credentials.** `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
  `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `apiKeyHelper`, GitHub tokens and
  App material are absent from the harness environment, argv and settings. Their
  presence is `BLOCKED`, not "overridden".
- **Sessions are not capabilities.** Session IDs, transcripts and checkpoints stay
  in the harness's namespace; resume needs the full ADR 008 binding, never a bare
  ID, `--continue`/`--last`, a transcript path or a latest-session search.
- **Config is untrusted until pinned.** Effective settings are computed from a
  closed, root-owned source set and compared to a pinned digest; repository
  `.claude/` content, `.mcp.json`, hooks, plugins, user and local settings are
  inventoried and denied or excluded. `CLAUDE.md`/`CLAUDE.local.md` conflicts keep
  the HAR-04 `CONFLICT` result.
- **No consumer-OAuth routing.** Claude subscription credentials are never routed
  through a gateway, proxy, `ANTHROPIC_BASE_URL`, `apiKeyHelper`, SDK or the Agent
  Platform broker. `--bare` is **not** a workaround (it uses no subscription) and is
  not a default for the shared `AGENTS.md` path.

## Trust-boundary model

Domains (each a separate OS principal and filesystem/namespace view; names are
design roles, not accounts or units):

| Domain | Trusted for | Must not hold or see |
| --- | --- | --- |
| **D1 Codex vendor process** | Its own login state and refresh, under its own `CODEX_HOME` | Claude home, Publisher/Signer material, Control Plane secrets |
| **D2 Claude vendor process** | Its own login state under its own `CLAUDE_CONFIG_DIR` | Codex home, Publisher/Signer material, Control Plane secrets |
| **D3 Tool domain** (shell, file tools, hooks, MCP servers, plugins, subagents spawned by D1/D2) | Nothing; hostile by assumption | Any credential, session store, config home, parent `/proc`, inherited FDs, other worktrees |
| **D4 Control Plane** | Assignment, admission, event sequencing, lineage | Provider tokens; it observes redacted lifecycle only |
| **D5 Worker supervisor** (future) | Process lifecycle, descendant reaping, redaction | Provider tokens, signer handles |
| **D6 Local config/session storage** | Vendor-owned files with 0700/0600 for the owner | Cross-harness or cross-worker readers, symlinks out of the home |
| **D7 GitHub App Publisher and Signer** | Per-worker App credentials ([PUB-02](draft-publisher.md)) | Anything provider-related; never reachable from D1-D3 |
| **D8 Operator** | Interactive login, approvals, merge | n/a (human, external to all JSON) |

Edges: D1/D2 → D3 is the **unproven** edge (S5: instructions are not enforcement;
`-p` runs repository hooks/MCP without a trust prompt (S2)). `AGENTS.md` and
`CLAUDE.md` are behavioral guidance and **never** an OS boundary; boundaries must
come from OS principals, mount/PID/network namespaces, seccomp/LSM or equivalent,
independently proven (Gate #73), not from the instruction files or vendor
permission modes alone. D7 never shares a principal, home or namespace with D1-D3.
Provider usage output is `UNAVAILABLE` in canonical events (ADR 008); no quota is
guessed or auto-switched.

## Threat model

Each row requires a denial or a retained uncertainty. All live probes are
`NOT_RUN`; the offline tests in this change check only the document/schema.

| ID | Threat | Required control or retained status | Negative proof (section "Negative-test plan") |
| --- | --- | --- | --- |
| T1 | Token passed via env, argv, FD, `/proc/<pid>/environ`/`cmdline`/`fd`/`mem`, ptrace or subprocess inheritance (e.g. `CLAUDE_CODE_OAUTH_TOKEN`) | No credential in env/argv; D3 cannot read D1/D2 process state; inherited FDs closed; no credential-bearing relay. Unproven today | NT-01..04 |
| T2 | Reading another user's or another harness's home (`~/.codex`, `~/.claude`, `.credentials.json`, `auth.json`, keyring), symlink/hardlink/bind escapes, `CLAUDE_CONFIG_DIR`/`CODEX_HOME` redirected | Separate principals and homes, no-follow opens, fixed config-home variables set by trusted bootstrap only | NT-05, NT-06 |
| T3 | Session recovery: stored transcripts/`--resume` of foreign sessions; machine-wide ID lookup (S3) | Namespaced lineage, exact checkpoint binding, `--no-session-persistence` only where it does not defeat required resume, no transcript path acceptance | NT-07, NT-08 |
| T4 | Unauthorized resume, cross-worker, cross-epoch or cross-harness continuation, replay of a stale assignment | ADR 008 fencing; resume BLOCKED until HAR-07/Gate #73 | NT-07 |
| T5 | Replaced or injected settings (`.claude/settings.json`, `settings.local.json` at the **main checkout root** for worktrees, `--settings`, managed, `CLAUDE_CONFIG_DIR`) | Effective-config digest pinned; closed setting-source list; deny writes by D3; compare before each effect | NT-09, NT-10 |
| T6 | Repository hooks, `.mcp.json`, plugins, subagents, skills or project `AGENTS.md`/`CLAUDE.md` that execute or steer without approval, including `-p` skipping the trust dialog | Complete route inventory with immutable denial; no `-p` for untrusted worktrees without proven exclusion; no `--bare` workaround | NT-11, NT-12 |
| T7 | Unsafe permission switches: `--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions`, `bypassPermissions`, `auto`, broad `--allowedTools`, `acceptEdits`, Codex approval/sandbox bypass flags | Closed argv allowlist generated by trusted code; any unknown/bypass flag `BLOCKED`; flags are never operator- or model-supplied | NT-13 |
| T8 | Over-broad tool permissions (Bash, network, other worktrees, secrets paths, Publisher IPC) | Least-privilege tool domain; deny by default; network egress fixed | NT-14 |
| T9 | Secrets in stderr, logs, transcripts, telemetry, crash dumps, `/status` or `claude auth status` output | Only redacted AP-HEVENT/1 leaves D5; no raw stderr/transcript export; no auth-status scans | NT-15 |
| T10 | Task or background agent still running after cancel, SIGTERM or timeout (background tasks, subagents, `--bg`, MCP tasks, `/loop` wakeups (S2)) | Process-tree death proof; background features disabled or reconciled; terminal event alone is not quiescence | NT-16 |
| T11 | Tool effect outcome unknown after interruption (SIGTERM leaves the turn unfinished (S2)) | Retain `OUTCOME_UNKNOWN`/`NEEDS_HUMAN`; no automatic replay | NT-17 |
| T12 | Confusing `harness_id`, `worker_id`, provider account, GitHub App or reviewer identity | Distinct typed fields; account is an opaque reference; harness change needs ADR 008 protocol | NT-18 |
| T13 | Silent switch to API billing (ambient key, S6), quota exhaustion and automatic fallback to the other harness/account | Ambient keys `BLOCKED`; no failover, no billing path change without row 8 approval | NT-19, NT-20 |
| T14 | Prompt injection from Issue/checkout/output claiming authority or instructing credential disclosure | Treated as data; authority only from direct human instruction and installed policy | NT-21 |
| T15 | Vendor documentation changes between review and use | Freshness limits and invalidation on pin change | NT-22 |

## Required evidence before any production harness invocation

Evidence is closed, bounded and secret-free: enumerated statuses, SHA-256 digests,
public references and UTC dates. It never contains tokens, account identifiers,
emails, home paths, raw stderr, transcripts or prompts.

| Class | Decision | Evidence | Status today |
| --- | --- | --- | --- |
| E-VEN-1 | A | Dated source digests for each cited vendor page and the exact account/plan type | NOT_PROVEN |
| E-VEN-2 | A | Written vendor clarification for the exact usage pattern (rows 4-6), or row 8 approval | NOT_PROVEN |
| E-VEN-3 | A | Re-observation within the freshness window and at the current CLI pin | NOT_RUN |
| E-ISO-1 | B | Credential store separation per harness and worker (principals, modes, mounts) | NOT_RUN |
| E-ISO-2 | B | Tool domain cannot read credentials via FD/proc/env/ptrace/memory/subprocess | NOT_RUN |
| E-ISO-3 | B | Effective settings/hooks/MCP/plugin/instruction-source inventory equals the pinned set | NOT_RUN |
| E-ISO-4 | B | Unsafe flags and ambient credentials rejected before any exec | NOT_RUN |
| E-ISO-5 | B | Output/telemetry redaction proof (stderr, logs, events) | NOT_RUN |
| E-ISO-6 | B | Process-tree death and background-work quiescence proof | NOT_RUN |
| E-ISO-7 | B | Resume/checkpoint binding and replay denial | NOT_RUN |
| E-ISO-8 | B | Fixed network egress and no billing-path change | NOT_RUN |
| E-ISO-9 | B | Publisher/Signer separation from provider and tool domains | NOT_RUN |
| E-OPR-1 | C | Human approval bound to worker, enrollment, harness, `selection_epoch`, configuration digest, this ADR's contract, expiry | NOT_RUN |

Freshness (**proposed**, to be confirmed by review): A evidence at most 30 days old
and re-observed on any CLI pin or terms change; B evidence valid only for the exact
binary/config/kernel/epoch digests; C expires with the epoch and an explicit deadline.

### Bounded secret-free diagnostic proposal

The closed [AP-HAUTH-EVIDENCE/1 schema](harness-auth-evidence.schema.json) and
[fabricated examples](harness-auth-evidence.examples.json) define a record that
holds only the three decision statuses, reason codes from a closed enum, digests
and dates. Per-status constraints are part of the schema: `NOT_RUN` has no evidence,
`observed_date` `NONE` and at least one reason; `NOT_PROVEN`/`BLOCKED` have at least
one reason and either no evidence with `NONE` or at least one digest with a date;
`ATTESTED_UNAUTHENTICATED` requires at least one unique evidence digest, a real
date and **no** blocking reasons. That status is an operator attestation that
evidence exists, never authentication of it and never a GO. Dates must be real
calendar dates in 2000-2099 (the schema pattern encodes month lengths and leap
years; the offline test cross-checks every day against `datetime.date`). Its `overall` is limited to `BLOCKED`, `NOT_PROVEN` or `NOT_RUN`;
`launch_allowed` and `production_go` are constant `false`. There is no loader,
validator, IPC or production consumer. Collecting such evidence must never involve
`claude auth status`, `claude setup-token`, `codex login status`, token or keyring
reads, or provider requests; evidence is derived from OS facts about files,
principals and processes, from document digests and from human attestations.

## Negative-test plan

Offline, expected-result catalogue. `This change` = verified by the document and
schema tests in `tests/test_harness_auth_terms_contract.py`; every other row is a
**future** test, `NOT_RUN`, owned by HAR-07/Gate #73 under separate authorization
with synthetic canaries (never real credentials).

| ID | Case | Expected | Where |
| --- | --- | --- | --- |
| NT-01 | Canary token in env readable from tool domain | BLOCKED | HAR-07 |
| NT-02 | Canary reachable via `/proc/<pid>/environ`, `cmdline`, `fd`, `mem`, ptrace | BLOCKED | HAR-07 |
| NT-03 | Inherited FD to credential file in a child | BLOCKED | HAR-07 |
| NT-04 | Credential passed in argv | BLOCKED | HAR-07 |
| NT-05 | Read other user's or other harness's home | BLOCKED | HAR-07 |
| NT-06 | Symlink/hardlink/bind from worktree to a home or store | BLOCKED | HAR-07 |
| NT-07 | Resume with foreign, stale, cross-harness, cross-worker or cross-epoch ID | BLOCKED | HAR-02/03 offline, HAR-07 live |
| NT-08 | Transcript-path or `--continue`/latest resume | BLOCKED | HAR-07 |
| NT-09 | Modified project/local/user/managed settings between admission and exec | BLOCKED | HAR-07 |
| NT-10 | Settings written through the worktree-to-main-checkout local file path | BLOCKED | HAR-07 |
| NT-11 | Repository hook or `.mcp.json` server present | BLOCKED | HAR-07 |
| NT-12 | Plugin or subagent definition in repository | BLOCKED | HAR-07 |
| NT-13 | `--dangerously-skip-permissions`, `bypassPermissions`, unknown flag | BLOCKED | HAR-07 |
| NT-14 | Tool reaches network or secrets path outside policy | BLOCKED | HAR-07 |
| NT-15 | Canary secret in stderr/log/telemetry output | redacted or BLOCKED | HAR-03 offline, HAR-07 |
| NT-16 | Descendant/background task survives cancel | NEEDS_HUMAN, quiescence unproven | HAR-07 |
| NT-17 | Interrupted tool effect | OUTCOME_UNKNOWN, no replay | HAR-03 offline, HAR-07 |
| NT-18 | Confused `harness_id`/`worker_id`/account/App fields | rejected by closed schemas | HAR-02 offline |
| NT-19 | `ANTHROPIC_API_KEY` or other ambient key present | BLOCKED | HAR-07 |
| NT-20 | Quota exhaustion triggers fallback/other harness/API key | none; NEEDS_HUMAN | HAR-02 offline |
| NT-21 | Issue text claims authority or asks for credentials | ignored as data | review |
| NT-22 | Stale vendor evidence or changed pin | `NOT_PROVEN` | this change (schema), HAR-07 |
| NT-23 | Evidence record with `production_go=true`, GO-like `overall`, extra or secret-like field | schema rejects | this change |
| NT-24 | Decision A satisfied while B or C missing | overall stays non-GO | this change (document rule) |
| NT-25 | `CLAUDE.md`/`CLAUDE.local.md` competing with `AGENTS.md` | CONFLICT | HAR-04 (existing tests) |
| NT-26 | Publisher/Signer material reachable from provider or tool domain | BLOCKED | HAR-07 |
| NT-27 | `ATTESTED_UNAUTHENTICATED` without evidence digests, with `observed_date=NONE`, with blocking reasons, or with an impossible calendar date; `NOT_RUN` carrying evidence | schema rejects | this change |

## Consequences

- Supervised personal use (rows 1-3) is documented and may continue unchanged under
  AGENTS.md section 1; this ADR adds no new permission to it.
- The product path for both harnesses stays blocked; the project's Claude path for
  automation has **no vendor-supported subscription route** that avoids credential
  custody. The realistic future options are (a) written vendor clarification that
  covers a private single-owner orchestrator, or (b) an explicit, separately
  approved API-billed design (row 8).
- No code, packaging, doctor, schema revision or host change results. `claude auth`
  and `codex login` commands remain operator-only and outside Agent Platform.
- Doctor/inventory results continue to mean installation facts only.

## Unresolved questions

1. Is a private, single-owner orchestrator that launches the unmodified Claude Code
   CLI on the owner's own subscription an "ordinary, individual usage", or "agent
   infrastructure" requiring Commercial Terms (S1)? **NOT_PROVEN.**
2. Is scripted `claude -p` by the account owner covered by consumer plan limits
   and terms, given S2 describes it as the Agent SDK path and S1 mentions both?
3. Same for `codex exec` on ChatGPT sign-in outside "enterprise and other trusted
   private automation" (S8), and whether a public repository changes it.
4. Whether any vendor-supported mechanism lets a trusted process run the CLI while
   the tool domain provably cannot read the credential (the D1/D2 → D3 edge).
5. Behaviour and enforcement of the vendor on scripted use (rate/quota accounting,
   account action) is unknown and unobserved.
6. Whether `claude setup-token`/`CLAUDE_CODE_OAUTH_TOKEN` delivered by the operator
   (not stored by Agent Platform) is treated as credential intermediation.
7. How the independent PKG-09 #138 packaging reconciles with HAR packaging
   (deferred to the human integrator; not merged here).

**Draft vendor clarification questions** (not sent; sending is an external action
requiring the operator's decision): *"Our private, single-user, self-hosted setup
launches your unmodified, official Claude Code CLI under the owner's own
subscription on a dedicated Linux VM, without sharing or storing the credential
outside the CLI's own configuration directory. Is (i) interactive use, (ii) owner-
started `claude -p`, and (iii) an owner-operated scheduler that starts unattended
sessions on the same account permitted under the Consumer Terms, and under what
conditions?"* An equivalent question applies to OpenAI for ChatGPT sign-in and
`codex exec`.

## Criteria for HAR-07 to proceed

HAR-07 ([#137](https://github.com/TechTradeExpress/Agent-Platform/issues/137)) may
start **design and separately authorized disposable experiments** only if all hold:

1. This ADR has been independently accepted on its **exact published HEAD** and that
   HEAD has positive hosted CI (`CI` and `Debian package`). **No merge of HAR-05 is
   required** for HAR-07 to begin DESIGN_ONLY work. The whole HAR-01..HAR-07 series
   stays Draft and unmerged into `main` until every review and CI run has finished;
   only the human maintainer merges.
2. For the targeted row, decision A is recorded as an explicit maintainer decision
   with dated sources and, for rows 4-6, a vendor clarification or an approved
   row 8 design. If none exists, HAR-07 is limited to non-credentialed offline
   isolation design.
3. The experiment uses synthetic canaries, no real provider credential, no provider
   request and no host privilege change unless separately authorized.
4. The experiment plan covers NT-01..NT-27 for the exact binary pinned in HAR-04.
5. Publisher/Signer independence, independent review and human-only merge are
   preserved in the plan.

Passing HAR-07 experiments would still not set any GO: B evidence feeds Gate #73,
and A and C remain separate decisions. Until then every path stays
`SUBSCRIPTION_ISOLATION_BLOCKED`, exit 13, `LIVE_NO_GO`, `HOST_NOT_RUN`.

## Validation boundary

Documentation, a closed JSON Schema and fabricated examples with offline tests only.
No Claude or Codex CLI invocation, login, `auth status`, token inspection, API
request, installation, host or GitHub change was performed. Test results are
reported in the review report, not asserted here.
