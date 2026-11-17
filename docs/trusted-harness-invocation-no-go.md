# ADR 010: trusted single-harness invocation and worker readiness (NO-GO plan)

**Contract:** AP-HINV/1. **Status:** PROPOSED / NO-GO / DESIGN_ONLY / SOURCE_ONLY /
OFFLINE_ONLY / NO_LIVE / HOST_NOT_RUN. **Issue:**
[HAR-07 #137](https://github.com/TechTradeExpress/Agent-Platform/issues/137), within
[HAR-00 #130](https://github.com/TechTradeExpress/Agent-Platform/issues/130).
**Stacked base:** published HAR-06 head `2cff431ffba3632baa11061f266ef8b2b7925692`
(tree `630178b9c67c3a9f9f2b193e25585bebc7422ad8`, Draft PR #146, `CI` and
`Debian package` SUCCESS at that head). Delivery of this change is local-only; a
later Draft PR targets `feature/issue-136-supervised-multi-harness-workflow` and
references the Issue with `Refs #137`, never `Closes`.

**Verdict: NO-GO.** This ADR specifies *what would have to be true* before the
Control Plane may ever launch exactly one approved harness on a worker. It enables
nothing. It adds no launcher, argv builder, login, credential handling, SDK use,
API-billed fallback, host change or provider request, and it defines **no GO state**:
every record it describes has `overall=NO_GO`, `launch_allowed=false` and
`production_go=false`. A later, separately reviewed ADR must introduce any positive
state (see [order of future Issues](#order-of-future-implementation-issues)).

It extends and **does not rewrite** [ADR 003](subscription-transport.md),
[ADR 004](architecture-trust-boundaries.md), [ADR 005](native-runtime-feasibility.md),
[ADR 007](debian-role-package-architecture.md), [ADR 008](multi-harness-architecture.md)
and [ADR 009](harness-auth-terms-isolation.md). Where this text could be read as
loosening any of them, the earlier, stricter text wins. Number 010 was chosen because
001-009 exist in the repository and 010 is unused (a repository-wide text search found no prior use).

Unchanged and binding: `SUBSCRIPTION_ISOLATION_BLOCKED` / public exit 13,
`LIVE_NO_GO`, `HOST_NOT_RUN`, Gate #73 BLOCKED, Publisher #108 BLOCKED, native
`run`/`resume`/`doctor` quarantine, one selected harness per worker, exactly two
Debian role packages (Control and Worker), one canonical root `AGENTS.md`, per-worker
GitHub App Publisher/Signer, independent review and **human-only merge**.

## Reading guide and non-goals

| Not in this ADR | Why |
| --- | --- |
| Launcher, supervisor, argv builder, session store, rotation tooling | Each needs its own Issue, review and operator authorization ([future Issues](#order-of-future-implementation-issues)) |
| Any provider CLI invocation, login, `auth status`, token inspection, model call | ADR 009 hard limits; the only provider facts here come from public documentation |
| Any change to HAR-01..HAR-06 code, to `instruction_sources.py` or to ADR 009 decisions | HAR-04 is frozen; a narrow corrective Issue is proposed instead ([U-1](#known-unresolved-requirements)) |
| A statement that supervised personal use is a product-run authorization | It is not (ADR 009 rows 1-3 vs 4-6) |
| Evidence that any host, kernel policy, BPF program or AppArmor profile works | HOST_NOT_RUN; offline tests prove document consistency only |

## Vendor documentation re-check (observed 2026-11-17)

Public pages were read as data only; no CLI, login or API request was made. The
decisions of ADR 009 (sources S1-S9, 2026-11-16) are **unchanged**. Pages are mutable;
two were only partly readable (the sandboxing page was read through character
100000 of 110890, the hooks page through 100000 of 294068) and the unread remainder is
NOT_RUN.

| ID | Source | Observed fact (short quote or paraphrase) | Consequence for this plan |
| --- | --- | --- | --- |
| V1 | [Claude legal and compliance](https://code.claude.com/docs/en/legal-and-compliance) | Same text as ADR 009 S1: OAuth "intended exclusively for purchasers" of subscription plans for ordinary use; developers building products, "including those using the Agent SDK", should use API-key authentication; no third-party Claude.ai login or routing through plan credentials; "may not collect, store, or intermediate Claude.ai credentials or session tokens"; limits "assume ordinary, individual usage"; running Claude Code in "hosted sandboxes or other agent infrastructure" requires Commercial Terms | Decision A stays NOT_PROVEN/BLOCKED for unattended orchestration; no new permission inferred |
| V2 | [Claude sandboxing](https://code.claude.com/docs/en/sandboxing) | Sandbox is **off by default**; Linux uses `bubblewrap`. "The sandbox covers shell commands only. Claude's file tools, MCP servers, and hooks run outside it." Default read policy "still allows reading credential files"; "There is no built-in credential deny list". Without platform support Claude Code "runs commands without sandboxing" unless `failIfUnavailable` is set; `excludedCommands` and the unsandboxed retry are escape hatches | The documented Claude sandbox is **not** complete mediation. File tools, MCP and hooks need separate OS confinement or denial. Fail-open default is unacceptable |
| V3 | [Claude settings](https://code.claude.com/docs/en/settings) | Precedence: managed, command line, project local, shared project, user. "In a worktree, it uses the file at the main checkout's root" for the local settings file. `--settings` outranks project and user files. `CLAUDE_CONFIG_DIR` relocates settings, history and plugins. Some permission keys are version-gated: `permissions.blockReadsOutsideWorkingDirectories` needs v2.1.257+, `blockWritesOutsideWorkingDirectories` v2.1.314+, `denyInsteadOfPrompting` v2.1.319+ | The HAR-04 pin 2.1.295 **lacks** the write-block and deny-instead-of-prompting keys. A pin change re-opens HAR-04 and decision B. The worktree-to-main-checkout path is a settings-injection route (NT-10 of ADR 009) |
| V4 | [Claude hooks](https://code.claude.com/docs/en/hooks) | Handlers "run in the current directory with Claude Code's environment" and inherit the parent environment; `if` filters are "best-effort, use the permission system rather than a hook to enforce"; skills' hooks register "including in a `-p` run in a folder you haven't trusted"; `allowManagedHooksOnly` (managed settings) blocks user, project, local and plugin hooks | Hooks are an execution route inheriting the environment; only managed policy can deny them. The environment passed to the harness must be a closed allowlist |
| V5 | [Codex approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security) (`developers.openai.com/codex/security` redirects to a Codex Security product page; this page is the sandbox reference) | Modes `read-only`, `workspace-write`, `danger-full-access`; approval `on-request`, `never`, `granular`. Network is off by default in `workspace-write`. `.git`, `.agents`, `.codex`, `.aws` are read-only even in writable roots. The network proxy "does not filter ... MCP server connections". `--dangerously-bypass-approvals-and-sandbox` (`--yolo`) disables both. Linux uses `bwrap` plus `seccomp`; in containers it "may not work". "Devcontainers do not prevent every attack ... a malicious project [can] exfiltrate anything available there, including Codex credentials" | Codex evidence and Claude evidence are different artifacts. MCP egress is outside the Codex proxy. Whole-container containment is not credential separation (consistent with ADR 004) |
| V6 | ADR 009 S2-S9 | Not re-read in this change | Their dates stay 2026-11-16; any use of them for a decision needs the 30-day freshness check |

**Compatibility of the plan with the documentation.** The plan uses no `claude -p`,
`--bare`, `setup-token`, Agent SDK, OAuth relay or API key, so it does not depend on
any ambiguous vendor clause; it keeps the unmodified official binary and
vendor-native sign-in by the human (V1). It uses vendor controls (managed settings,
permission rules, sandbox, Codex sandbox mode) only as defence in depth and treats
their documented gaps (V2, V4, V5) as reasons for OS-level confinement. Where the
documentation is silent or version-gated the plan records UNKNOWN or NOT_PROVEN, not
support. No statement above is a vendor authorization.

None of V2-V5 states that a vendor mode provides *exhaustive* tool mediation or
credential separation against hostile model-directed code; the project therefore
continues to require OS-level proof (ADR 004, Gate #73).

## Architectural execution flow (future, NOT enabled)

Domains reuse ADR 009 D1-D8: D1 Codex vendor process, D2 Claude vendor process,
D3 tool domain (hostile by assumption), D4 Control Plane, D5 worker supervisor,
D6 local config/session storage, D7 GitHub App Publisher and Signer, D8 operator.
Steps are requirements; each lists the gate that must hold before it may run.

| Step | Actor | Action | Must hold first | Fails closed to |
| --- | --- | --- | --- | --- |
| P0 | D8 | Approves one `harness_id` for one worker, epoch and exact pins through an authenticated operator path (AP-HSEL/1) | Decision C record for this worker and epoch (HC-01, HC-20) | no selection, admission BLOCKED |
| P1 | D4 | Admits an immutable AP-HASSIGN/1 assignment bound to selection digest, worker, epoch, task authorization | HAR-02 checks; scheduler chooses a worker, never a harness | STOP `ASSIGNMENT_HARNESS_MISMATCH` and siblings |
| P2 | D5 | Re-verifies binding, executable, instruction sources, effective configuration and host evidence immediately before effects | HC-02..HC-07, HC-11, HC-14, HC-24 | STOP/BLOCKED before any process |
| P3 | D5 | Creates the confinement (principals, namespaces, mounts, network, LSM/BPF) and starts D1 or D2 from the pinned absolute executable by descriptor-bound exec | HC-03, HC-08..HC-14 | BLOCKED, nothing started |
| P4 | D1/D2 | Runs the vendor CLI in its own account domain; tools run in D3 | Decisions A and B; unsafe flags and ambient credentials absent (HC-19, HC-25) | BLOCKED |
| P5 | D5 | Observes only bounded, redacted lifecycle events; maps them to AP-HEVENT/1; enforces timeouts | HC-05, HC-16 | NEEDS_HUMAN `PROTOCOL_INVALID` |
| P6 | D5/D4 | Cancels or times out the whole process tree; records one terminal state; any doubt keeps `OUTCOME_UNKNOWN` | HC-15 | NEEDS_HUMAN `CANCEL_UNCONFIRMED` |
| P7 | D4 | Records the attempt in the global continuity journal; accepts a candidate artifact only as data | HC-22 | NEEDS_HUMAN |
| P8 | D7 | A separate per-worker Publisher/Signer, driven by a separately authorized one-shot job, may publish an exact-SHA Draft | HC-17 (#108 pilots) | no publication |
| P9 | independent reviewer, D8 | Independent exact-HEAD review, human-only merge | HC-18 | unchanged AP-SM/2 |

Nothing in P0-P9 can be driven by task text, model output, Issue content, an
environment variable, CLI output or a failure of the selected harness.

## 1. Trusted binding: assignment, worker, epoch, harness, executable

Requirements (BC-n are testable and appear in the negative matrix):

- **BC-1 One scalar.** The worker's AP-HSEL/1 selection holds exactly one
  `harness_id` (`codex` or `claude_code`). Missing, `auto`, list-valued, case-changed
  or dual values are STOP. The scheduler picks a worker under existing authority,
  never a harness per task.
- **BC-2 Issuer.** The selection record comes from the trusted operator path and a
  root-owned installed policy; a checkout, Issue, model output, environment variable
  or self-signed worker file is not an issuer (ADR 008). HAR-02 typed objects remain
  *syntax*, not authentication.
- **BC-3 Exact comparison chain.** `worker + enrollment/boot + harness_id +
  selection_epoch + capability revision + configuration + executable manifest +
  parser + instruction + isolation digests` are compared at admission,
  acknowledgement, before effects, at resume and at result acceptance. Any drift
  invalidates the assignment; hashing alone does not prove freshness.
- **BC-4 Release provenance.** The executable comes from the pinned official release:
  signed manifest verified by Agent Platform itself (HAR-04: key fingerprint,
  manifest and binary SHA-256, `linux-x64` glibc), never `curl | sh`, a system package
  repository or a personal installation. The `manifestSignatureEnforcement: flag`
  observation means the vendor script does not enforce the signature; the project
  must. Binary download and ELF/ABI closure are NOT_RUN (HC-02, HC-04).
- **BC-5 Absolute, descriptor-bound exec.** The launcher opens the verified file
  without following symlinks, validates owner, mode and hash on the open descriptor
  and executes that descriptor (or an equivalent race-free binding). Re-opening by
  path after verification is BLOCKED. `PATH`, aliases, wrappers, shell functions,
  `CLAUDE_CODE_*`/`CODEX_*` executable overrides and personal installs never select
  a binary. A binary found on `PATH` is inventory, **not** the selected harness.
- **BC-6 No self-update.** The managed copy is root-owned and read-only; the
  documented `DISABLE_UPDATES` setting (HAR-04) is part of the pinned environment and
  an update attempt is a failure, not a retry.
- **BC-7 Capability and parser compatibility.** The AP-HCAP/1 row and the parser
  revision are bound to the exact executable. HAR-03's Claude profile is a project
  subset over synthetic fixtures; compatibility with the official stream is
  NOT_PROVEN ([U-3](#known-unresolved-requirements)). Codex's parser evidence is pinned
  to 0.164.0 and says nothing about a 0.166.0 binary.
- **BC-8 Instruction sources.** The exact root `AGENTS.md` digest is pinned and the
  effective instruction sources are enumerated: project-scope `CLAUDE.md`,
  `.claude/CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.override.md` and nested files are
  conflicts; the operator's user-level `~/.claude/CLAUDE.md` is **not** a conflict
  (vendor memory documentation, HAR-06) and is never read or moved. Loading is
  confirmed only by an in-session observation, never by file presence.
- **BC-9 Harness never unlocks authority.** The harness identity grants no GitHub
  writer credential, Signer handle, review verdict, Ready, Issue closure or merge. A supervised personal CLI session (AGENTS.md section 1) is not a
  product-run authorization, and a tool detected on a worker is not a selection.
- **BC-10 One active attempt.** At most one RESERVED, PREPARED, RUNNING or UNKNOWN
  attempt per worker, across boots, epochs and restores.

## 2. Complete mediation and per-harness confinement

Mediation is proven per harness, per exact binary and configuration, over **every**
route by which model-directed behaviour can cause an effect. A route is *mediated*,
*immutably disabled* or *UNKNOWN*; UNKNOWN is BLOCKED. Evidence for one harness is
never reused for the other (ADR 008, Issue #137 scope item 2).

| Route | Codex (ADR 005 / V5) | Claude Code (V2-V4) | Required control and proof |
| --- | --- | --- | --- |
| Shell/exec/PTY and child processes | `workspace-write` uses `bwrap`+`seccomp` on Linux; coverage of every spawn path UNKNOWN for the product binary | Bash sandbox is opt-in and off by default; fail-open without platform support unless `failIfUnavailable` | OS principal + namespaces and seccomp/LSM enforced by D5 regardless of vendor mode; descendants in the same cgroup; HC-10, HC-12 |
| File read/write/search tools | Internal handlers; `.git`/`.codex` read-only in writable roots | "File tools ... run outside" the sandbox; permission rules only | Mount/namespace denial of credential, config-home, other-worktree and common-Git-dir paths; no-follow opens; symlink/hardlink/bind negatives |
| Network and web tools | Off by default in `workspace-write`; proxy "does not filter" MCP | Sandbox proxy is hostname-based and TCP-only; WebFetch/WebSearch follow permission rules | Fixed provider endpoints only through D5-controlled egress (BPF/AppArmor/nftables as separately proven); no billing-path change; HC-13 |
| MCP servers, connectors, plugins | Egress outside the proxy | MCP and hooks "run outside" the sandbox | Immutable denial (none installed, none discoverable, project `.mcp.json` ignored); HC-11 |
| Hooks | Not covered by the sandbox page | Inherit environment; only managed settings can disable or restrict (`allowManagedHooksOnly`, `disableAllHooks`) | Managed policy plus closed environment allowlist; project/user/local hooks absent; HC-11 |
| Subagents, skills, background tasks, scheduled wakeups | UNKNOWN | UNKNOWN; `--bg`/background and `/loop` are quiescence risks (ADR 009 T10) | Disabled or reconciled; no unattended wakeup; HC-15 |
| Settings and instruction injection | project `.codex`, `AGENTS.override.md` | project/local settings (including the main-checkout local file for worktrees), `--settings`, `CLAUDE_CONFIG_DIR`, `.claude/rules` | Effective configuration computed from a closed root-owned source set, digest compared before every effect; D3 cannot write any source; HC-11 |
| Approval and permission bypass | `--dangerously-bypass-approvals-and-sandbox`, `danger-full-access`, `never` policy | `--dangerously-skip-permissions`, `bypassPermissions`, `auto`, broad `--allowedTools`, `acceptEdits` | Closed argv allowlist generated by trusted code; any unknown or bypass flag is BLOCKED before exec (NT-13) |
| Credentials: file, env, FD, proc, memory | `CODEX_HOME` auth store | `CLAUDE_CONFIG_DIR` credentials; default sandbox read policy still reads credential files | Separate OS principals for D1/D2 and D3; closed env; FD closure; `/proc` hidepid or PID namespace; ptrace denied; HC-08, HC-09 |

Rules:

1. Vendor permission modes, `AGENTS.md`, `CLAUDE.md`, hooks and permission rules are
   *behavioral* controls. The security boundary is the OS-enforced D5 confinement
   that holds even if every vendor control is bypassed or misconfigured.
2. A VM or container around the whole CLI does not separate the credential-owning
   process from its own tools (ADR 004). D1/D2 and D3 are distinct principals or
   namespaces, with the credential store reachable only from D1/D2.
3. Claude requires its own proof set: confinement keys available at the pinned release
   (V3), the managed settings file as the policy vehicle, no reliance on the
   shell-only sandbox, and an effective-settings check at each start. The existing
   Codex source evidence (0.164.0) does not transfer.
4. Adversarial inputs are part of the plan: prompt injection in Issues and checkout
   content, hostile project settings, hostile `AGENTS.md` text, symlinked worktrees,
   and tool output that imitates authority. All are data.

## 3. Accounts, configuration, credentials and sessions

Inherited from ADR 009 and made testable here:

- **AC-1** Vendor-owned interactive login by the human only. Agent Platform never
  collects, mirrors, proxies, refreshes or logs tokens, never reads `auth.json`,
  `.credentials.json`, keyrings or `~/.claude.json`, and never invokes `login`,
  `auth status` or `setup-token`.
- **AC-2** One account domain per worker and harness: `CODEX_HOME` and
  `CLAUDE_CONFIG_DIR` are set by trusted bootstrap to per-worker, per-harness
  directories owned by the coding identity, never shared, never the operator's
  personal home, and unreachable from the other harness and from D3.
- **AC-3** Both CLI identities and account domains remain separate even on one host;
  coexistence of Codex login, Claude login and Publisher material on one worker is
  NOT_PROVEN (ADR 009 row 10) and requires its own proof.
- **AC-4** Ambient `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
  `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `apiKeyHelper`, GitHub tokens and App
  material are absent from environment, argv and settings. Presence is BLOCKED, never
  "overridden".
- **AC-5** Sessions are not capabilities: no resume by bare ID, `--continue`, latest
  search, transcript path, other worker, other epoch or other harness.
- **AC-6** Telemetry, update checks and crash reporting use fixed, reviewed settings;
  nothing from them reaches D3 or the journal in raw form.

## 4. Filesystem and network control

Requirements (all HOST_NOT_RUN):

- **FS-1** D3 sees only the task worktree (read/write), a read-only pinned toolchain
  closure and private tmp/dev/proc. The common Git directory, other worktrees, state
  directories, journals, config homes and credential stores are absent from its mount
  namespace.
- **FS-2** Writes to instruction and settings sources (`AGENTS.md` ancestors,
  `.claude/`, `.codex/`, `.mcp.json`, hooks, plugin directories, the main-checkout
  local settings file) are denied to D3; a change invalidates admission.
- **FS-3** Egress is a fixed allowlist of the selected provider's endpoints reachable
  only by D1/D2; D3 has no route. Dynamic endpoints (redirects, telemetry, update
  hosts, marketplaces) are denied unless pinned. BPF and AppArmor policies count only
  when **enforcement is measured active**: an installed but inactive program or
  profile is not evidence and is BLOCKED (`ENFORCEMENT_INACTIVE`).
- **FS-4** The model-provider route and the GitHub route use different principals and
  network policy (see [authority separation](#8-authority-separation)).

## 5. Process control, cancellation and interruption

State model (canonical states from ADR 008, closed here with explicit transitions):

| From | Event | To | Notes |
| --- | --- | --- | --- |
| IDLE | admitted assignment, all preflight checks | RESERVED | single-writer CAS; not a process |
| RESERVED | confinement created and verified | PREPARED | nothing executed yet |
| PREPARED | descriptor-bound exec succeeded | RUNNING | observation, not liveness proof |
| RUNNING | exact terminal event and matching exit, process tree dead, no background work | FINISHED | not publication authority |
| RUNNING | cancel, timeout, crash, parser error, resource limit or operator abort | QUIESCING | whole process tree and cgroup signalled |
| QUIESCING | death of every descendant proven and effects reconciled | FINISHED | still no replay |
| QUIESCING | any doubt about death or effects | OUTCOME_UNKNOWN | retained intent |
| OUTCOME_UNKNOWN | independent operator reconciliation | FINISHED | only a new, separately admitted attempt may follow |
| any | selection, epoch, executable, configuration or instruction drift | BLOCKED | assignment invalid |

Requirements:

- **PC-1** All processes of an attempt share one kill domain (cgroup/PID namespace).
  Cancellation is bounded: graceful signal, then forced kill, then verification; each
  step has a deadline. A terminal event, exit code 143 or an expired lease alone does
  not prove quiescence (ADR 008, HAR-03: SIGTERM leaves the turn unfinished).
- **PC-2** Background tasks, subagents, scheduled wakeups and MCP tasks are disabled
  or reconciled; any observed background activity keeps effect completion UNKNOWN.
- **PC-3** Timeouts are enforced by D5 on wall time, output size, event count and
  resources, independently of the vendor CLI.
- **PC-4** Operator interrupt, host reboot and supervisor crash all end in
  QUIESCING or OUTCOME_UNKNOWN on recovery; none resumes automatically.
- **PC-5** Orphan cleanup is part of recovery: after a crash, D5 must find and kill
  surviving members of the kill domain before any new attempt is considered.

## 6. No automatic fallback or switching

- **NF-1** Quota exhaustion, authentication failure, crash, missing tool, parser
  failure or vendor outage never selects the other harness, another account, an API
  key or another worker's session.
- **NF-2** A task, Issue, model output, environment variable, CLI flag or CLI output
  cannot change `harness_id`; such a request is DENY `HARNESS_SWITCH_DENIED`.
- **NF-3** There is no import, conversion or resume of native sessions across
  harnesses, workers, epochs or hosts.
- **NF-4** The other harness's binary may be inventoried (HAR-04) but is never
  executed and its absence or presence changes no state.

## 7. Safe harness rotation (design only)

Rotation is an operator-mediated maintenance event, never a task-time reaction
(ADR 008 change protocol, made concrete with evidence):

| Step | Required outcome | Evidence (HC) | Stop |
| --- | --- | --- | --- |
| R1 Drain | New assignments and resume rejected; selection enters QUIESCING by CAS | HC-23 | any attempt in RESERVED/PREPARED/RUNNING |
| R2 Quiesce | Every process tree dead (cgroup empty), background work reconciled | HC-15 | any survivor or unknown |
| R3 Reconcile | Every retained and UNKNOWN intent reconciled under incident authority; external effects checked read-only | HC-22 | any UNKNOWN remains: RECONCILING/BLOCKED |
| R4 Re-attest | New executable, configuration, instruction, parser and isolation pins verified; decisions A and B re-decided for the new harness; host evidence refreshed | HC-02..HC-14, HC-19, HC-24 | any NOT_PROVEN/NOT_RUN |
| R5 Re-authorize | Fresh operator approval over the exact reconciled evidence and replacement record | HC-20 | missing or stale approval |
| R6 Commit | Atomic selection with epoch + 1, previous digest and independently anchored continuity; old assignments invalid | HC-01 | crash mid-commit: read-only reconciliation, no retry |
| R7 Resume work | New assignments, new native sessions; old sessions stay in their namespace; switching back is another full rotation | HC-21 | any reuse of an old session |

The two CLI identities, account domains and homes stay separate throughout; no
credential moves between them. Any UNKNOWN run forbids rotation. Rollback is "stay
drained or BLOCKED", never an automatic return to the earlier harness or epoch.

## 8. Authority separation

- **AS-1** Model-provider credentials (D1/D2) and GitHub App Publisher/Signer
  material (D7) never share a principal, home, namespace, FD, socket or log. D7 is
  unreachable from D1-D3; a provider token never authenticates to GitHub.
- **AS-2** The Publisher stays per-worker, exact-SHA and one-shot under separately
  authorized jobs ([PUB-02](draft-publisher.md), [worker publisher](worker-publisher.md)).
  Real Publisher pilots (#108) remain BLOCKED and independent of this plan; the
  harness output is a candidate artifact, never a publication grant.
- **AS-3** Independent review follows [AP-SM/2](solo-maintainer-policy.md): a different
  harness is not an independent reviewer, and a harness identity never performs the
  gated COMMENT, Ready or Issue-completed transitions. The HAR series stays Draft
  and unmerged until all seven Issues have exact-HEAD review and hosted CI.
- **AS-4** Merge is human-only. No harness, Publisher, Signer or CI identity may
  merge or enable auto-merge.

## 9. Continuity journal, bounded evidence, idempotency and replay

- **CJ-1** A global, single-writer, append-only continuity journal records every
  attempt reference, assignment digest, task identity digest, worker, epoch, harness,
  state transitions and terminal observation. It is anchored independently of the
  worker's local disk; a restored database plus a restored local anchor is not
  continuity (HAR-02). Durable CAS and anchoring are NOT_IMPLEMENTED.
- **CJ-2** Replay is denied by attempt reference, assignment digest, authorization
  digest and stable task identity, including FINISHED records, across workers.
  Unrelated FINISHED history never grants a retry.
- **CJ-3** Artifacts crossing the D3-to-D4 boundary have exact digests and size
  bounds; a candidate is accepted once and idempotently, and its acceptance never
  implies publication.
- **CJ-4** Evidence and logs are bounded (events, bytes, depth) and redacted:
  closed enums, digests, public references and UTC dates only. No prompts,
  transcripts, raw stderr, account identifiers, emails, tokens or home paths.
- **CJ-5** Usage and cost are UNAVAILABLE; no guessed counts, reset times or
  billing-path changes.
- **CJ-6** No blind replay: an interrupted or UNKNOWN attempt is never re-run to
  "see what happens"; a new attempt needs new authorization after reconciliation.

Operational metrics permitted (all bounded, redacted, non-secret): counters of
admissions, STOP/BLOCKED codes, state transitions, cancel/timeout outcomes, journal
write failures and evidence age; never content. Log redaction is tested with canary
strings (HP-08, NI-18).

## 10. Separate admission of worker01 and worker02

- **HA-1** Each worker has its own AP-HINV-EVIDENCE/1 record, own selection epoch,
  own Decision C and its own host attestation. Nothing is inherited between workers,
  between harnesses or between epochs (`inherited_approval` is the constant `false`).
- **HA-2** Order: worker01 is considered first, worker02 only by a separate approval
  after worker01's evidence and rollback have been reviewed. Neither is hard-wired to a
  harness; the Codex/Claude split suggested in HAR-00 is not a setting.
- **HA-3** worker01's installed worker package (`0.1.0-7`, operator-reported) is
  package proof only: it shows installed bits, not isolation, execution binding or
  authorization. worker02 has no inherited approval and its observed state (existence
  check only, content unread) includes the HAR-04 scanner false alarm.
- **HA-4** A fresh worker doctor report (HAR-04 contract) is necessary host evidence
  but never changes `configuration`, `execution_binding` or `launch_allowed`.

## 11. Gates A, B and C and the evidence schema

Unchanged from ADR 009: **A** vendor permission, **B** isolation and process safety,
**C** operator approval are independent, all required, and fail closed. This ADR adds
the per-host checks of the table below and a closed evidence record,
[AP-HINV-EVIDENCE/1](harness-invocation-evidence.schema.json) with
[fabricated examples](harness-invocation-evidence.examples.json).

Evidence statuses are exactly: `SOURCE_ONLY` (reviewed source/document),
`DISPOSABLE_FIXTURE` (synthetic or disposable-VM run), `HOST_NOT_RUN`, `NOT_PROVEN`,
`BLOCKED`, `OPERATOR_ATTESTED_UNAUTHENTICATED` and `INDEPENDENTLY_VERIFIED` (real
host observation by an independent reviewer, with a verification reference). The
schema ties each status to its allowed origin, evidence digests and a real calendar
date, so a synthetic origin can never carry `INDEPENDENTLY_VERIFIED`. Even a record in
which every check is `INDEPENDENTLY_VERIFIED` keeps `overall=NO_GO`: **no synthetic
or attested evidence, and no evidence at all in this revision, can set GO.** The
schema fixes `launch_allowed=false`, `production_go=false` and
`inherited_approval=false`; a GO state requires a new ADR and schema revision.
The schema also requires that `checks` hold exactly 25 items in which each of
`HC-01`..`HC-25` occurs exactly once (`allOf` of one `contains` with
`minContains` = `maxContains` = 1 per identifier, in addition to `uniqueItems`), so a
duplicated identifier can neither replace nor hide another check.

Closed set of 25 readiness checks (`check_id` values of the schema). Gate `-` marks authority-separation checks that are independent of A/B/C. **Current status** is the same for both workers in this revision; the statuses are claims about the repository at this commit, not about any host.

| Check | Schema name | Requirement | Gate | Owner Issue | Current status |
| --- | --- | --- | --- | --- | --- |
| HC-01 | `selection_record_issued_by_trusted_operator_path` | Selection record issued by the trusted operator path, epoch continuity | C | FI-07 | SOURCE_ONLY |
| HC-02 | `executable_release_signature_and_provenance` | Executable release signature and provenance verified by Agent Platform | B | FI-05 | SOURCE_ONLY |
| HC-03 | `absolute_executable_binding_no_path_alias_env` | Absolute, descriptor-bound executable; no PATH, alias or env selection | B | FI-05 | NOT_PROVEN |
| HC-04 | `candidate_elf_abi_and_library_closure` | Candidate ELF, ABI and library closure | B | FI-05 | HOST_NOT_RUN |
| HC-05 | `official_wire_format_parser_compatibility` | Official wire-format and parser compatibility, including failure streams | B | FI-08 | NOT_PROVEN |
| HC-06 | `agents_md_load_observed_in_session` | `AGENTS.md` load observed in the real session; no competing source | B | FI-03 | HOST_NOT_RUN |
| HC-07 | `instruction_scanner_user_level_false_positive_corrected` | Instruction scanner user-level false positive corrected | B | FI-01 | BLOCKED |
| HC-08 | `account_home_and_credential_store_isolation` | Account home and credential store isolation per harness and worker | B | FI-06 | HOST_NOT_RUN |
| HC-09 | `tool_domain_cannot_reach_credentials_fd_proc_env` | Tool domain cannot reach credentials (FD, proc, env, ptrace, memory) | B | FI-06 | HOST_NOT_RUN |
| HC-10 | `complete_tool_mediation_including_children` | Complete tool mediation including children (Gate #73) | B | FI-06 | BLOCKED |
| HC-11 | `settings_hooks_plugins_mcp_inventory_pinned` | Settings, hooks, plugins and MCP inventory equals the pinned set | B | FI-06 | NOT_PROVEN |
| HC-12 | `filesystem_confinement` | Filesystem confinement | B | FI-06 | HOST_NOT_RUN |
| HC-13 | `network_egress_confinement` | Network egress confinement | B | FI-06 | HOST_NOT_RUN |
| HC-14 | `host_enforcement_active_apparmor_bpf` | Host enforcement measured active (AppArmor, BPF) | B | FI-10, FI-11 | HOST_NOT_RUN |
| HC-15 | `process_tree_termination_and_cancellation` | Process-tree termination and cancellation | B | FI-07 | NOT_PROVEN |
| HC-16 | `output_redaction_and_telemetry_control` | Output redaction and telemetry control | B | FI-07 | SOURCE_ONLY |
| HC-17 | `publisher_signer_separation` | Publisher and Signer separation (#108) | - | FI-09 | BLOCKED |
| HC-18 | `independent_review_and_human_merge_separation` | Independent review and human-only merge separation | - | FI-09 | SOURCE_ONLY |
| HC-19 | `vendor_terms_decision_a` | Vendor terms decision A recorded for the exact usage pattern | A | FI-02 | NOT_PROVEN |
| HC-20 | `operator_authorization_decision_c_per_host` | Operator authorization decision C for this worker and epoch | C | FI-10, FI-11 | HOST_NOT_RUN |
| HC-21 | `session_continuity_and_no_cross_harness_resume` | Session continuity; no cross-harness resume | B | FI-07 | SOURCE_ONLY |
| HC-22 | `journal_receipt_continuity_and_idempotency` | Journal and receipt continuity, idempotency, replay denial | B | FI-07 | NOT_PROVEN |
| HC-23 | `rotation_drain_quiesce_reattestation` | Rotation: drain, quiesce, reconciliation, re-attestation | C | FI-12 | NOT_PROVEN |
| HC-24 | `host_attestation_and_worker_doctor_per_host` | Host attestation and fresh worker doctor per host | B | FI-10, FI-11 | HOST_NOT_RUN |
| HC-25 | `no_api_fallback_or_billing_path_change` | No API-key fallback or billing-path change | A | FI-02 | SOURCE_ONLY |

Freshness (proposed, confirm in review): decision A evidence at most 30 days and
re-observed on any CLI pin or terms change; B evidence only for the exact binary,
configuration, kernel and epoch digests; C expires with the epoch and a deadline.

## Known unresolved requirements

Each item is a **separate readiness condition**; none is resolved here.

| ID | Requirement | Status | Prerequisite and owner |
| --- | --- | --- | --- |
| U-1 | HAR-04 `instruction_sources.diagnose` reports `CONFLICT` / `claude_md_in_ancestor` when only the operator's `<home>/.claude/CLAUDE.md` exists (existence check; content never read), although the vendor memory documentation loads it alongside `AGENTS.md`. This is a false alarm in a frozen module | BLOCKED (HC-07) until corrected | FI-01 narrow source-only fix with regression tests, before any native-runtime readiness assessment |
| U-2 | No observation that `AGENTS.md` is actually loaded by Claude Code or Codex on worker02 (or worker01) | HOST_NOT_RUN (HC-06) | FI-03 operator-attended observation per [HAR-06 procedure](supervised-multi-harness-workflow.md), recorded as AP-INSTRUCTION-LOAD-EVIDENCE/1; file presence is never evidence |
| U-3 | HAR-03 parser fixtures are `SYNTHETIC_NOT_CAPTURED` project-owned subsets; compatibility with the official Claude Code stream (success, failure, denial, interruption, background) is unverified. A real capture needs a provider session, which is blocked by decision A for scripted use | NOT_PROVEN (HC-05) | FI-08 plan; executable-safe validation (static, `--version`/help-class in a disposable VM only if separately authorized) cannot prove wire compatibility; blocked on A |
| U-4 | Effective isolation limits of Claude Code (sandbox is shell-only and opt-in; file tools/MCP/hooks outside; credentials readable by default; version-gated keys absent at the pin) | NOT_PROVEN / BLOCKED (HC-10) | FI-06 confinement design and disposable canary tests; Gate #73 |
| U-5 | Vendor permission for ambiguous automated or unattended orchestration (ADR 009 rows 4-8; V1) | NOT_PROVEN / BLOCKED (HC-19) | FI-02 written vendor clarification or an approved API-billed design (explicitly out of scope here) |
| U-6 | Codex exact-binary equivalence: evidence pinned to 0.164.0; installed 0.166.0 is operator-reported and unproven | NOT_PROVEN | FI-06 per-binary evidence |
| U-7 | Durable single-writer CAS, independent continuity anchor, rollback resistance | NOT_IMPLEMENTED (HC-22) | FI-07 |
| U-8 | BPF/AppArmor active enforcement on each host, not merely installed | HOST_NOT_RUN (HC-14) | FI-10, FI-11 |
| U-9 | Publisher #108 and Gate #73 | BLOCKED (HC-17, HC-10) | independent of this ADR |
| U-10 | Maintainer confirmation of the AP-SM/2 "Codex CLI" role reading and of the stacked-PR `Refs` rule | DECIDED in HAR-06 review; not re-opened | none |

### Proposed narrow correction for U-1 (not applied here)

Open a separate source-only Issue (FI-01, working title "HAR-04a: exempt only the
operator's user-level Claude file from the ancestor conflict scan"):

1. Scope: `src/agent_platform/instruction_sources.py` and its tests only; no doctor,
   packaging, schema or runtime change; `load_confirmed` stays always `false`.
2. Behaviour: accept an explicit, trusted `user_config_home` argument (default none,
   meaning today's behaviour). Exempt exactly `<user_config_home>/.claude/CLAUDE.md`
   by existence check without reading it and without following symlinks; report a
   separate `user_level_file_present` boolean. Never derive the exemption from the
   environment or `HOME` implicitly, and never exempt any other ancestor file.
3. Regression tests: user file only gives `CONSISTENT_UNVERIFIED` with the flag;
   project `CLAUDE.md`, `CLAUDE.local.md`, `.claude/CLAUDE.md` in the project or in a
   non-user ancestor still give `CONFLICT`; user file plus project file gives
   `CONFLICT`; a symlinked or non-regular user file gives `CONFLICT`; a different
   directory named `.claude` one level above is not exempt; unreadable (mode 000)
   user file is handled by existence only; `load_confirmed` stays `false`; version
   floor and `AGENTS.override.md` cases unchanged.
4. Acceptance: independent review, then HC-07 may leave BLOCKED; it never implies
   HC-06.

## Threat model and trust boundaries

Assume hostile Issue, checkout, model output, repository settings and alternate
installed tools. Trusted: the independently admitted controller/operator and the
separately protected bootstrap. Residual and unresolved: root or hypervisor
compromise, a compromised provider binary, shared-host rollback, unproven complete
mediation and account eligibility.

| ID | Threat | Control | Test |
| --- | --- | --- | --- |
| TM-1 | PATH, alias, env or wrapper selects a different executable | BC-5 descriptor-bound pinned exec | NI-04..NI-07 |
| TM-2 | Executable swapped between check and exec | no-follow descriptor identity | NI-08 |
| TM-3 | Task or model chooses or switches harness | BC-1, NF-2 | NI-01, NI-02, NI-19 |
| TM-4 | Tool domain reads credentials via env, FD, proc, memory, ptrace, symlink | AC-2, FS-1, separate principals | NI-12, NI-13 |
| TM-5 | Hooks, plugins, MCP, subagents or settings inject execution | complete route inventory, managed policy | NI-14, NI-15 |
| TM-6 | Shell-only sandbox mistaken for complete mediation | rule 1 of section 2 | NI-16 |
| TM-7 | Inactive BPF/AppArmor treated as enforcement | FS-3 measured activity | NI-17 |
| TM-8 | Surviving descendant after cancel | PC-1, PC-5 | NI-20 |
| TM-9 | Blind replay or duplicate attempt | CJ-2, BC-10 | NI-21, NI-22 |
| TM-10 | API key or OAuth relay used to continue | AC-1, AC-4, NF-1 | NI-11, NI-18 |
| TM-11 | Provider identity reaches GitHub writer or merge authority | AS-1..AS-4 | NI-23, NI-24 |
| TM-12 | Synthetic or attested evidence promoted to readiness | section 11 schema | NI-25, NI-26 |
| TM-13 | Approval inherited from another worker, harness or epoch | HA-1 | NI-10 |
| TM-14 | Stale or modified vendor terms or documents | freshness limits | NI-27 |
| TM-15 | Secrets in logs, telemetry, events or journals | CJ-4 redaction | NI-28 |

## Test matrix

Offline status of each row: **this change** means checked by
`tests/test_harness_invocation_contract.py` over documents, schema or the
test-only reference evaluator; every other row is a **future** test, NOT_RUN, to be
specified in its own Issue and run only under separate authorization with synthetic
canaries (never real credentials, never a real provider request).

### Positive tests

| ID | Case | Expected | Status |
| --- | --- | --- | --- |
| HP-01 | Evaluator with all preconditions hypothetically satisfied | NO_GO `LAUNCHER_NOT_IMPLEMENTED` (never GO) | this change |
| HP-02 | Operator's user-level `~/.claude/CLAUDE.md` present and otherwise ideal | not a conflict | this change |
| HP-03 | Schema accepts the five fabricated records and keeps `overall=NO_GO` | accepted | this change |
| HP-04 | Document, schema, scenario fixture and checklist agree (IDs, statuses, links) | consistent | this change |
| HP-05 | Descriptor-bound exec of a synthetic executable matches pinned hash | binding PASS | future (FI-05) |
| HP-06 | Canary token only in D1/D2 domain is unreachable from D3 | PASS | future (FI-06) |
| HP-07 | Cancel kills a synthetic process tree and the cgroup is empty | QUIESCED | future (FI-07) |
| HP-08 | Canary secret in synthetic stderr is redacted from events and logs | redacted | future (FI-07) |
| HP-09 | Rotation drill with synthetic harness stubs reaches epoch + 1 only after R1-R6 | PASS | future (FI-12) |
| HP-10 | Observed in-session `AGENTS.md` load recorded by the operator | evidence record | future (FI-03) |

### Negative tests

| ID | Case | Expected | Status |
| --- | --- | --- | --- |
| NI-01 | Unselected, dual or `auto` harness | STOP | this change (S-03, S-04) |
| NI-02 | Assignment harness or worker differs from the selection | STOP | this change (S-05, S-06) |
| NI-03 | Epoch rollback, unauthenticated selection, configuration drift | STOP | this change (S-07..S-09) |
| NI-04 | PATH, alias, env override or personal install selects the binary | STOP | this change (S-10..S-13) |
| NI-05 | Binary reopened by path (swap race) | STOP | this change (S-14) |
| NI-06 | Hash mismatch; unverified release; unverified ELF closure | STOP/BLOCKED | this change (S-15..S-17) |
| NI-07 | Real swapped inode, library or interpreter | BLOCKED | future (FI-05) |
| NI-08 | Real race between verification and exec | BLOCKED | future (FI-05) |
| NI-09 | Project instruction conflict; load not observed; scanner uncorrected; parser unverified | STOP/BLOCKED | this change (S-18, S-20..S-22) |
| NI-10 | Gate A, B or C missing; approval inherited or from a previous epoch | BLOCKED | this change (S-23..S-29) |
| NI-11 | Ambient key, API fallback, OAuth relay, bypass flag | BLOCKED | this change (S-30..S-33) |
| NI-12 | Canary credential via env, argv, FD, `/proc`, ptrace | BLOCKED | future (FI-06) |
| NI-13 | Read other harness home, other worker home, symlink or bind escape | BLOCKED | future (FI-06) |
| NI-14 | Repository hook, `.mcp.json`, plugin or subagent definition | BLOCKED | future (FI-06) |
| NI-15 | Settings changed between admission and exec, including the main-checkout local settings file | BLOCKED | future (FI-06) |
| NI-16 | Mediation incomplete; hooks, plugins or MCP not denied | BLOCKED | this change (S-34, S-35); real probes future |
| NI-17 | BPF/AppArmor inactive or unknown; stale doctor evidence | BLOCKED | this change (S-36..S-38) |
| NI-18 | Canary secret in stderr, log, telemetry or journal | redacted or BLOCKED | future (FI-07) |
| NI-19 | Task text or failure switches harness | DENY | this change (S-46, S-47) |
| NI-20 | Descendant or background task survives cancel | NEEDS_HUMAN | this change (S-56, S-57); real probe future |
| NI-21 | Second attempt, UNKNOWN retained, replay | BLOCKED | this change (S-39..S-41) |
| NI-22 | Resume across harness, worker, epoch or host | BLOCKED | this change (S-42) |
| NI-23 | Publisher or Signer material reachable from provider or tool domain | BLOCKED | this change (S-44); real probe future |
| NI-24 | Harness identity marks Ready, closes Issue or merges | DENY | this change (S-48, S-49) |
| NI-25 | Synthetic evidence used as readiness | BLOCKED | this change (S-45) |
| NI-26 | Evidence record with GO, `production_go=true`, inherited approval, secret-like field, synthetic origin marked verified, impossible date | schema rejects | this change |
| NI-27 | Stale vendor evidence or changed pin | NOT_PROVEN | schema/freshness rule this change; live re-observation future |
| NI-28 | Raw prompt, transcript or account identifier in an evidence record | schema rejects | this change |
| NI-29 | Rotation with active attempt, UNKNOWN outcome, no death proof, no re-attestation or no approval | BLOCKED | this change (S-50..S-54) |

### Scenario outcomes checked by the reference evaluator

Decision vocabulary: **STOP** identity/binding mismatch before effects, **BLOCKED**
unmet gate or evidence, **DENY** forbidden action, **NEEDS_HUMAN** uncertain outcome,
**NO_GO** all modelled preconditions hold but nothing is implemented. There is no GO.

| ID | Scenario | Decision | Code |
| --- | --- | --- | --- |
| S-01 | Every precondition hypothetically satisfied: still no launcher exists | NO_GO | `LAUNCHER_NOT_IMPLEMENTED` |
| S-02 | Same hypothetical preconditions for worker01 with Codex | NO_GO | `LAUNCHER_NOT_IMPLEMENTED` |
| S-03 | No harness selected for the worker | STOP | `HARNESS_UNSELECTED` |
| S-04 | Two harnesses selected at once | STOP | `HARNESS_AMBIGUOUS` |
| S-05 | Assignment names a different harness than the worker selection | STOP | `ASSIGNMENT_HARNESS_MISMATCH` |
| S-06 | Assignment bound to another worker or enrollment | STOP | `WORKER_MISMATCH` |
| S-07 | Selection epoch differs from assignment (rollback or stale) | STOP | `EPOCH_MISMATCH` |
| S-08 | Selection record not issued by the trusted operator path | STOP | `SELECTION_UNAUTHENTICATED` |
| S-09 | Effective configuration digest differs from the pinned digest | STOP | `CONFIG_DIGEST_MISMATCH` |
| S-10 | Executable found by PATH lookup | STOP | `EXEC_NOT_PINNED` |
| S-11 | Executable resolved through a shell alias | STOP | `EXEC_NOT_PINNED` |
| S-12 | Executable path taken from an environment variable | STOP | `EXEC_NOT_PINNED` |
| S-13 | Operator's personal installation used instead of the managed binary | STOP | `EXEC_NOT_PINNED` |
| S-14 | Executable reopened by path after verification (swap race) | STOP | `EXEC_REOPEN_RACE` |
| S-15 | Executable SHA-256 differs from the pinned value | STOP | `EXEC_HASH_MISMATCH` |
| S-16 | Release signature or provenance not verified | BLOCKED | `RELEASE_UNVERIFIED` |
| S-17 | Candidate ELF, ABI or library closure not verified | BLOCKED | `ELF_UNVERIFIED` |
| S-18 | Project CLAUDE.md or CLAUDE.local.md competes with AGENTS.md | STOP | `INSTRUCTION_CONFLICT` |
| S-19 | Operator's user-level ~/.claude/CLAUDE.md present, otherwise ideal | NO_GO | `LAUNCHER_NOT_IMPLEMENTED` |
| S-20 | AGENTS.md load not observed in the actual session | BLOCKED | `LOAD_NOT_OBSERVED` |
| S-21 | HAR-04 scanner false positive not yet corrected (Claude) | BLOCKED | `SCANNER_UNCORRECTED` |
| S-22 | Parser compatibility with the official stream not verified | BLOCKED | `PARSER_UNVERIFIED` |
| S-23 | Decision A (vendor permission) NOT_PROVEN | BLOCKED | `VENDOR_NOT_PROVEN` |
| S-24 | Decision A BLOCKED for subscription automation | BLOCKED | `VENDOR_NOT_PROVEN` |
| S-25 | Decision B (isolation) not run | BLOCKED | `ISOLATION_NOT_PROVEN` |
| S-26 | Decision B only DISPOSABLE_FIXTURE, not host evidence | BLOCKED | `ISOLATION_NOT_PROVEN` |
| S-27 | Decision C missing for this worker | BLOCKED | `OPERATOR_NOT_APPROVED` |
| S-28 | Decision C inherited from the other worker | BLOCKED | `APPROVAL_INHERITED` |
| S-29 | Decision C approved for the previous epoch only | BLOCKED | `OPERATOR_NOT_APPROVED` |
| S-30 | Ambient ANTHROPIC_API_KEY or equivalent in the environment | BLOCKED | `AMBIENT_CREDENTIAL` |
| S-31 | API-key fallback configured after quota | BLOCKED | `API_FALLBACK_FORBIDDEN` |
| S-32 | OAuth relay, proxy or setup-token delivery by the platform | BLOCKED | `OAUTH_RELAY_FORBIDDEN` |
| S-33 | Bypass-permissions or unknown flag present | BLOCKED | `UNSAFE_FLAG` |
| S-34 | Tool mediation incomplete (some route unmediated) | BLOCKED | `MEDIATION_INCOMPLETE` |
| S-35 | Hooks, plugins or MCP servers not denied | BLOCKED | `HOOKS_MCP_PLUGINS_ENABLED` |
| S-36 | BPF/AppArmor policy installed but inactive | BLOCKED | `ENFORCEMENT_INACTIVE` |
| S-37 | Enforcement state unknown | BLOCKED | `ENFORCEMENT_INACTIVE` |
| S-38 | Worker doctor evidence stale | BLOCKED | `HOST_EVIDENCE_STALE` |
| S-39 | A second attempt while one is active | BLOCKED | `ACTIVE_ATTEMPT_EXISTS` |
| S-40 | New attempt while an earlier outcome is UNKNOWN | BLOCKED | `UNKNOWN_OUTCOME_RETAINED` |
| S-41 | Replay of an earlier assignment or task identity | BLOCKED | `REPLAY_DENIED` |
| S-42 | Resume with a foreign-harness session | BLOCKED | `CROSS_HARNESS_RESUME_DENIED` |
| S-43 | Resume with every precondition satisfied: still no launcher | NO_GO | `LAUNCHER_NOT_IMPLEMENTED` |
| S-44 | Publisher or Signer material reachable from the provider or tool domain | BLOCKED | `PUBLISHER_REACHABLE` |
| S-45 | Readiness claimed from synthetic or disposable evidence | BLOCKED | `SYNTHETIC_NOT_PROOF` |
| S-46 | Task or model output asks to choose the harness | DENY | `HARNESS_SWITCH_DENIED` |
| S-47 | Automatic switch to the other harness after a failure or quota | DENY | `HARNESS_SWITCH_DENIED` |
| S-48 | Harness identity asked to mark Ready or close the Issue | DENY | `READY_NOT_HARNESS` |
| S-49 | Harness identity asked to merge | DENY | `MERGE_HUMAN_ONLY` |
| S-50 | Rotation requested with an attempt still active | BLOCKED | `ROTATION_NOT_DRAINED` |
| S-51 | Rotation requested with an UNKNOWN outcome retained | BLOCKED | `ROTATION_UNRECONCILED` |
| S-52 | Rotation without proof of process-tree death | BLOCKED | `PROCESS_DEATH_UNPROVEN` |
| S-53 | Rotation without re-attestation of the new pins | BLOCKED | `ROTATION_NOT_REATTESTED` |
| S-54 | Rotation without fresh operator approval | BLOCKED | `ROTATION_NOT_APPROVED` |
| S-55 | Rotation with every step satisfied: still not implemented | NO_GO | `ROTATION_NOT_IMPLEMENTED` |
| S-56 | Cancellation without process-tree death proof | NEEDS_HUMAN | `CANCEL_UNCONFIRMED` |
| S-57 | Timeout with external effects not reconciled | NEEDS_HUMAN | `OUTCOME_UNKNOWN` |
| S-58 | Cancellation fully proven and reconciled: record only, no replay | NO_GO | `LAUNCHER_NOT_IMPLEMENTED` |

Evaluation order: forbidden actions, publisher reachability, then (for launch, resume
and rotation) harness identity, binding, executable, instruction sources, decisions
A/B/C, credentials, mediation, host enforcement, continuity, evidence origin, and
finally the unconditional `NO_GO`. The evaluator is test infrastructure, not shipped
code; its truth table is documentation of this ADR and proves nothing about a host.

## Entry conditions, stop conditions and rollback

**Entry conditions for starting any future implementation Issue** (all required):

1. This ADR is accepted on its exact published HEAD with positive hosted CI, and the
   whole HAR-01..HAR-07 series has finished independent review and CI; merge stays
   human-only and bottom-up by the maintainer.
2. The Issue is directly assigned by the human, names its mode (A, B or C), and states
   publication explicitly (HAR-06).
3. FI-01 (scanner correction) is accepted before any task that reads
   `instruction_sources` for Claude readiness.
4. For anything touching a provider: decision A is recorded for the exact usage
   pattern or the work is limited to credential-free offline design.
5. For anything touching a host: a separate, host-specific operator approval exists
   for that worker and epoch.

**STOP conditions** (any one ends the work and reports the exact blocker): an unknown
or unproven required capability; unavailable official documentation or changed terms;
a competing project instruction source; an unverified executable; any credential
reachable from D3; measured-inactive enforcement; a surviving process after cancel;
an UNKNOWN outcome; a need for sudo, package installation, host mutation, login or a
provider request that is not separately authorized; any pressure to select the other
harness or an API key to "get around" a gate.

**Rollback** for any future live step is defined before it starts: revert to the
drained, BLOCKED selection; kill and verify the kill domain empty; revoke the
approval; preserve journal and evidence; never restore an earlier epoch or session;
no automatic retry. This ADR itself is documentation and tests only and rolls back by
reverting its commit.

## Per-worker GO/NO-GO checklist

The checklist is **per worker** and per epoch. Every row must be
`INDEPENDENTLY_VERIFIED` on that worker for a future operator to even consider a GO,
which this ADR cannot grant. Current state for both workers is below; columns are
separate because approval and evidence are never shared.

### worker01 (considered first) and worker02 (separate approval)

| Check | Requirement | worker01 | worker02 |
| --- | --- | --- | --- |
| HC-01 | Selection record issued by the trusted operator path, epoch continuity | SOURCE_ONLY | SOURCE_ONLY |
| HC-02 | Executable release signature and provenance verified by Agent Platform | SOURCE_ONLY | SOURCE_ONLY |
| HC-03 | Absolute, descriptor-bound executable; no PATH, alias or env selection | NOT_PROVEN | NOT_PROVEN |
| HC-04 | Candidate ELF, ABI and library closure | HOST_NOT_RUN | HOST_NOT_RUN |
| HC-05 | Official wire-format and parser compatibility, including failure streams | NOT_PROVEN | NOT_PROVEN |
| HC-06 | `AGENTS.md` load observed in the real session; no competing source | HOST_NOT_RUN | HOST_NOT_RUN |
| HC-07 | Instruction scanner user-level false positive corrected | BLOCKED | BLOCKED |
| HC-08 | Account home and credential store isolation per harness and worker | HOST_NOT_RUN | HOST_NOT_RUN |
| HC-09 | Tool domain cannot reach credentials (FD, proc, env, ptrace, memory) | HOST_NOT_RUN | HOST_NOT_RUN |
| HC-10 | Complete tool mediation including children (Gate #73) | BLOCKED | BLOCKED |
| HC-11 | Settings, hooks, plugins and MCP inventory equals the pinned set | NOT_PROVEN | NOT_PROVEN |
| HC-12 | Filesystem confinement | HOST_NOT_RUN | HOST_NOT_RUN |
| HC-13 | Network egress confinement | HOST_NOT_RUN | HOST_NOT_RUN |
| HC-14 | Host enforcement measured active (AppArmor, BPF) | HOST_NOT_RUN | HOST_NOT_RUN |
| HC-15 | Process-tree termination and cancellation | NOT_PROVEN | NOT_PROVEN |
| HC-16 | Output redaction and telemetry control | SOURCE_ONLY | SOURCE_ONLY |
| HC-17 | Publisher and Signer separation (#108) | BLOCKED | BLOCKED |
| HC-18 | Independent review and human-only merge separation | SOURCE_ONLY | SOURCE_ONLY |
| HC-19 | Vendor terms decision A recorded for the exact usage pattern | NOT_PROVEN | NOT_PROVEN |
| HC-20 | Operator authorization decision C for this worker and epoch | HOST_NOT_RUN | HOST_NOT_RUN |
| HC-21 | Session continuity; no cross-harness resume | SOURCE_ONLY | SOURCE_ONLY |
| HC-22 | Journal and receipt continuity, idempotency, replay denial | NOT_PROVEN | NOT_PROVEN |
| HC-23 | Rotation: drain, quiesce, reconciliation, re-attestation | NOT_PROVEN | NOT_PROVEN |
| HC-24 | Host attestation and fresh worker doctor per host | HOST_NOT_RUN | HOST_NOT_RUN |
| HC-25 | No API-key fallback or billing-path change | SOURCE_ONLY | SOURCE_ONLY |

worker01: installed package `0.1.0-7` is package proof only. worker02: no inherited approval; HC-07 stays BLOCKED until FI-01 and HC-06 stays HOST_NOT_RUN until FI-03. Neither worker has a decision C, an enforcement measurement or an independently verified isolation result in this repository.

Operator GO/NO-GO questions for a future review (all must be answered YES with
evidence; today every answer is NO):

1. Is exactly one harness selected for this worker and epoch, through the trusted
   operator path, with no other harness executable reachable by the launcher?
2. Is the executable the pinned, signature-verified release bound by descriptor?
3. Was the `AGENTS.md` load observed in the actual session, and does no project
   instruction source compete?
4. Is vendor permission (A) recorded for this exact usage pattern, and is
   isolation (B) independently verified on this host for this binary and
   configuration, and approval (C) given for this worker, epoch and deadline?
5. Is every tool route mediated or immutably disabled, with measured-active
   OS enforcement, and is the credential domain unreachable from tools?
6. Are cancellation, kill-domain death, journal continuity and replay denial proven?
7. Are Publisher/Signer and merge authority independent of the provider identity, and
   does Gate #73 permit this path?
8. Is rollback defined, rehearsed on a disposable host and approved?

## Order of future implementation Issues

None of these Issues exists yet; each needs its own assignment, mode, review and, for
host or provider contact, separate operator authorization. Order is by dependency.

| Order | Working title | Scope | Depends on | Acceptance |
| --- | --- | --- | --- | --- |
| FI-01 | HAR-04a scanner correction | source-only change in `instruction_sources.py` with regression tests ([proposal](#proposed-narrow-correction-for-u-1-not-applied-here)) | this ADR reviewed | tests above; HC-07 only |
| FI-02 | Vendor clarification and decision A record | maintainer decision documents; no code | ADR 009 | dated sources or written clarification; HC-19, HC-25 |
| FI-03 | Instruction-load observation records | operator-attended observation per HAR-06 for each harness and worker | FI-01 | HC-06 per worker |
| FI-04 | Disposable canary fixture specification | per-harness, credential-free fixture extending AP-NCF/1 (#28) | ADR 004/005 | independently reviewed spec; no real run |
| FI-05 | Executable binding primitive | source-only, tested with a synthetic executable | FI-04 | NI-04..NI-08 offline |
| FI-06 | Per-harness confinement and mediation profiles | design plus disposable canary tests (separately authorized) | FI-04, Gate #73 | HC-08..HC-13 |
| FI-07 | Supervisor, kill domain, cancellation, durable journal | source-only first, then disposable | FI-05 | HC-01, HC-15, HC-16, HC-21, HC-22 |
| FI-08 | Wire-format validation plan | per-harness validation design, blocked on decision A for scripted use | FI-02 | HC-05 |
| FI-09 | Publisher/Signer separation evidence | per-host, independent of this series (#108) | #108 pilots | HC-17, HC-18 |
| FI-10 | worker01 host attestation | separate operator approval; fresh doctor, enforcement measurement | FI-05..FI-09 | HC-14, HC-24, HC-20 for worker01 |
| FI-11 | worker02 host attestation | separate approval after FI-10 review; nothing inherited | FI-10 | same for worker02 |
| FI-12 | Rotation procedure | operator tooling and drill with synthetic stubs | FI-07 | HC-23 |
| FI-13 | GO-state ADR and launcher | introduces any positive state; inert until every row above is accepted | FI-01..FI-12 | new ADR 011 and schema revision |

## Consequences

- Supervised personal use (ADR 009 rows 1-3) is unchanged; this ADR adds no permission.
- The product path for both harnesses stays blocked at exit 13; Claude native product
  runtime stays BLOCKED because product-controlled subscription use is not authorized
  and no OAuth routing or billable API fallback is permitted.
- The deliverable is a **plan with testable gates**, not progress toward enablement:
  passing every offline test here changes no host and no readiness status.
- No code, packaging, doctor, workflow, schema revision of earlier contracts or host
  change results.

## Validation boundary

Documentation, a closed JSON Schema, fabricated examples, a scenario fixture and
offline tests only. No Claude or Codex CLI invocation, login, `auth status`, token
inspection, API request, installation, binary fetch, host, kernel-policy, systemd or
GitHub change was performed. Results are reported in the review report, not asserted
here. Hosted CI and Debian lifecycle for this change are NOT_RUN until publication.
