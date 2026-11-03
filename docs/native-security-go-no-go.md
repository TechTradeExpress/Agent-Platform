# Native tool / credential boundary GO/NO-GO — Issue #51

Specification **AP-NS/1**, 2026-11-03. Decision: **NO-GO** to native autonomous
activation; security decision **NO** for the reported same-domain design,
**UNKNOWN** for exhaustive mediation. Assessment result **BLOCKED**, native runtime
still **SUBSCRIPTION_ISOLATION_BLOCKED / exit 13**. This offline increment adds a
pure bounded assessment API and mock traces, not an adapter, launcher or authority.

[ADR 004](architecture-trust-boundaries.md), [ADR 003](subscription-transport.md),
[ADR 002](tool-dispatch-feasibility.md), [native adapter](native-codex.md),
[auth boundary](subscription-auth.md) and [AP-NCF/1](native-linux-fixture.md) remain
binding. Stock Codex CLI on the operator's ChatGPT subscription is the sole
selected future engine. A custom agent, API fallback, OAuth forwarding, wider
sandbox or credential proxy is not a remedy authorized here. The supervised
interactive developer Codex session is separate from the blocked product runtime.

## Exact subject and evidence ledger

This is the historical **0.164.0** subject, not whatever CLI is installed today:

- Upstream `openai/codex`, annotated tag `rust-v0.164.0`, tag object
  `fe3b29455488c2e189e43ad5526a107900c5e1b7`, peeled commit
  `6aaac694803004a63c6f393d153c96d22521a6b9`.
- Candidate `x86_64-unknown-linux-musl`, 308,139,304 bytes, SHA-256
  `b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306`.
- Runtime cap remains 268,435,456 bytes; candidate admission **BLOCKED**.
  The separate 384 MiB static inspection ceiling is not a runtime cap increase.
- Source/build equivalence **UNKNOWN**. A tag, blob/hash, advertised version or
  successful parser/schema extraction does not attest the installed binary.
- Repository assessment base `86191eaface389322cd64ad5e10c2eccb07ba8ba`, the verified
  PR #57 human squash merge. No CLI was invoked or inspected for this assessment.
  dev01's previously recorded interactive 0.166.0 does not update these pins or
  establish any property investigated for 0.164.0.

| ID / available trace | Provenance and verdict | What it does not establish |
| --- | --- | --- |
| E1 [recorded static audit](tool-dispatch-evidence.json), [interpretation](tool-dispatch-feasibility.md) | Prior partial pinned-source/blob and generated-schema observations; callback subset supported, separate built-ins observed | No new full upstream source/dependency audit, immutable inventory, artifact equivalence or exhaustive runtime interception |
| E2 [fabricated transcript](../tests/fixtures/codex-0.164.0/transcript.json), `tool_dispatch_probe` | VERIFIED_OFFLINE parser/mock denial contract; fabricated IDs, never sent | No server handshake, native turn, auth, real cancellation or same-session resume |
| E3 [sandbox01 JSON](fixtures/native-canary-v1/sandbox01-report.json), [provenance](fixtures/native-canary-v1/sandbox01-provenance.json) | OPERATOR_REPORTED_REMOTE_SNAPSHOT labelled REAL_KERNEL_SYNTHETIC; host/worker PASS, same-domain FAIL, overall BLOCKED/exit 13 | Not independently reenacted or artifact-audited; not every stock tool; not credential isolation, keyring audit or native mediation |
| E4 [fixture input gaps](fixtures/native-canary-v1/fixture-plan.json) | BLOCKED_MISSING_INPUTS; reviewed AP-NCF/1 specification | External scripts, runtime manifest bytes, exact package provenance/raw logs remain missing; no reproduced/signed fixture build |
| E5 [AP-NS/1 baseline](native-security-assessment.json), new `native_security.assess` tests | VERIFIED_OFFLINE deterministic evidence classification and sanitized mock traces only | Types/digests/mock PASS cannot authenticate provenance or promote kernel/auth/production readiness |
| E6 Auth/refresh/account and admitted native runtime | AUTH_E2E_NOT_RUN, NOT_RUN/BLOCKED | No login, account eligibility, live subscription turn or complete trusted-Codex/untrusted-tool domain established |

The E1 source files were not newly fetched or executed here; their exact paths,
Git blob IDs and prior findings are retained in E1. Full source/schema bundles are
not vendored. Conclusions below are a consolidation of that **recorded partial
static inspection**, not a new independent source-to-binary audit. Any additional
or unknown path is blocking, even if absent from this inventory. Historical
fixture JSON remains unchanged; correlation hashes are not signatures or approval.

## Pinned route inventory

`Dispatch` means whether E1 establishes interception by the experimental
external dynamic-tool callback. **UNSUPPORTED** means that proposed callback does
not cover the observed separate handler; it is not a claim no future supported
interface can exist. `Boundary` means verified OS-enforced credential separation
or immutable positive disablement for the whole route. **No route is currently
VERIFIED_MEDIATED**. S1–S6 link to exact-commit source paths/blobs in ADR 002;
`schema_inventory` is E1's generated methods, not proof of model reachability.

| Route ID / scope | Dispatch | Boundary | Evidence / missing proof |
| --- | --- | --- | --- |
| dynamic_tools: explicit function/namespace | SUPPORTED_SUBSET | UNKNOWN | S1/S2, dynamic handler pending-response path; schema/mock subset only, no real transport or confined worker |
| shell_exec: unified exec and one-shot fallback | UNSUPPORTED | UNKNOWN | S1 internal ExecCommandHandler; disabling unified exec can expose fallback; every fallback must be denied or mediated |
| pty: terminal allocation and session process | UNSUPPORTED | UNKNOWN | Same internal exec path; PTY, FD ownership and child lifetime not externally attested |
| write_stdin: ongoing terminal I/O | UNSUPPORTED | UNKNOWN | S1 WriteStdinHandler; continuation can act after initial approval/turn; bind exact process/epoch |
| patch: direct and shell-intercepted patch | UNSUPPORTED | UNKNOWN | S1/S3 ApplyPatchHandler/intercept_apply_patch, local/remote routes; no universal external replacement |
| file_reads: read/search/list/image/resources | UNKNOWN | UNKNOWN | S1/S4, view image, shell and MCP paths; in-process/implicit file reads incomplete audit |
| file_mutations: create/write/copy/remove/metadata | UNKNOWN | UNKNOWN | Experimental fs APIs in schema inventory; client API is not necessarily a model callback; transitive reachability incomplete |
| mcp_connectors: servers/resources/apps/reload | UNSUPPORTED | UNKNOWN | S1/S4 distinct runtime and resource handlers; URLs, server processes, resources and reload not covered by dynamic callback |
| plugins_skills: discovery/install/instructions | UNKNOWN | UNKNOWN | S1 + schemas; disabledPluginIds explicitly not a capability filter in recorded schema; loader/installer can alter reachability |
| js_code_mode: execute/wait/nested calls | UNKNOWN | UNKNOWN | S5 nested registry and local/remote hosts; JS worker, nested invocation, wait/interrupt need full boundary |
| hooks: pre/post and lifecycle commands | UNKNOWN | UNKNOWN | S2 conditional hooks around internal execution; not universal interception; hook spawning/inherited FDs unproved |
| background_children: queues/jobs/descendants | UNKNOWN | UNKNOWN | Exec/write_stdin, backgroundTerminals, queue/process APIs; post-turn persistence and descendants not exhausted |
| subagents: spawn/resume/followup V1/V2 | UNSUPPORTED | UNKNOWN | S1/S6 separate handlers and inherited effective config/role overrides; every child inventory and credential identity unproved |
| hosted_tools: web/model/provider tools | UNKNOWN | UNKNOWN | S1 hosted tools excluded from router inventory metrics; provider result path/disablement incomplete |
| resume_fork_replay: resume/fork/inject/compact/new context | UNKNOWN | UNKNOWN | Schemas permit config/history changes; exact session and immutable boundary after transition unproved |
| cancellation: interrupt/disconnect/reaping | UNKNOWN | UNKNOWN | Schema and mock local cancellation only; native acknowledgements, drain and child-death guarantees untested |
| credential_refresh_persistence | UNKNOWN | UNKNOWN | Not necessarily a dispatched tool; auth writes, token refresh, keyring and session poisoning not fully audited |
| implicit_config_session_reads | UNKNOWN | UNKNOWN | Startup, instruction/config/plugin/history reads may precede dispatch; no hostile code may share trusted auth process |
| remote_alternate_dispatch | UNKNOWN | UNKNOWN | Remote environments, direct fs/process/config, review/realtime APIs; deny unused ingress and audit alternate paths |
| approvals_control_tools | UNKNOWN | UNKNOWN | S1 permissions/user input/control/tools; approvals are policy decisions, not execution/result substitution or OS isolation |

A tool name allowlist, frozen dynamicTools list, environment filtering, same-UID
0700 permissions, read-only auth mount, approval prompt or model instruction does
not provide complete mediation. Same UID can open files, keyrings and Unix
sockets, inspect proc/parent memory or inherited FDs, tamper with sessions or
persist children. Tools need neither direct Internet nor file write access to
exfiltrate readable tokens through stdout, images, MCP, model-bound output or
allowed inference egress. Host containment and the inner auth boundary are
separate claims. The existing Python canary does not execute stock native tools.

## Required supported upstream interface (proposal, not implemented)

A reconsideration requires a documented, exact-build supported contract, plus
independent code/OS proof, with all of the following:

1. Immutable exhaustive inventory/negotiation for built-ins, implicit operations,
   plugins/MCP/hooks/hosted tools and all child/alternate routes. Unknown/new tools
   default to denial. No config/model/role/server reload may widen the inventory;
   detect drift before effects, including resume/fork/reconnect/new context.
2. Every model-directed operation either runs exclusively in an OS-separated
   credential-free worker or is positively and immutably disabled. Approval hooks
   or extra dynamic functions cannot substitute for bypassing internal handlers.
   Trusted Codex auth/refresh/persistence stays outside hostile code, not merely
   behind another directory in the same UID/process. Prove no tool can invoke a
   hidden in-process file/process/network operation before or after mediation.
3. Credential owner and tools have denied cross-process proc/memory/ptrace,
   keyring, mount, FD and IPC/socket access; explicit descriptor closure and typed
   bounded transport only. No account/token/CODEX_HOME/session/control-plane/
   publisher mount or privileged socket in the worker. Account inference egress
   belongs only to trusted Codex, never a token-forwarding API broker.
4. Supported per-call/session/turn/process identity, immutable operation, exact
   arguments/scope and runtime/build pins, anti-replay epochs, one response and
   timeout/disconnect semantics. Session UUIDs/digests are correlation, not
   identity authentication. Bind worker results to the originating operation;
   no partial success or uncertain write is safe to replay.
5. Explicit cancellation drain and child termination/reaping proof across
   background jobs, hooks, PTYs, nested tools and subagents. Prevent persistence
   across turn boundaries unless separately designed; parent death or recorded
   terminal state alone is insufficient. Resume must retain exact session and
   audited inventory; never choose recent session or silently adopt changed config.
6. Full pinned artifact/source equivalence, runtime closure/admission and reviewed
   fixture supply chain. Tests must run under this **actual native route**, not an
   unrelated Bubblewrap command. Fresh exact-build independent review is required
   after changes. No flag or receipt here enables authentication or execution.

No such complete supported contract has been demonstrated by the recorded source
and schema evidence. Unsupported/unknown rows require upstream work or additional
independent proof, not a custom inference runner or relaxed sandbox. App-server
experimental dynamic tools alone do not authorize changing ADR 003's selected
stock-CLI product architecture.

## Synthetic negative-probe design and trace contract

**Design only for future separately approved disposable, credential-free fixture**;
all real probes below are NOT_RUN by this assessment. No VM connection, canary,
Codex executable, login/store/keyring query, inference or security change is
performed. AP-NCF/1 missing-input review must be completed first; provisioning and
each later real probe need separate direct human permission. dev01 is not that VM.

For each applicable route above, test both a denied synthetic asset and a permitted
workspace control. Bind traces to source/artifact/tool/profile hashes, canonical
route, session/turn/worker/epoch correlation, operation and fake asset ID. Never
use real credentials or authenticated developer processes. Retain booleans/fixed
verdicts and evidence class, not raw commands, token-like contents, paths or stderr.
Start with no sensitive inherited environment/FD/socket and mandatory namespaces;
prove identities/mounts/NoNewPrivs/caps before attempts. Absence of a working
positive control or complete trace is BLOCKED, not denial PASS.

| Probe kind | Fabricated fixture-only experiment / required denial | Existing evidence and gap |
| --- | --- | --- |
| file_keyring | Fake auth/session files and a fixture-owned fake keyring service; deny read/write/traversal/alias and service access from tools | E3 file sentinels only; real keyring APIs not tested and must not be queried here |
| proc_parent_memory | Fixture-owned dummy parent PID, proc/fd/memory and controlled ptrace/process-memory attempts; deny access without disclosing contents | E3 synthetic sentinel proc checks; not real Codex parent-memory or all syscall coverage |
| inherited_fds | Deliberately inheritable synthetic descriptor/socket sentinel; prove absent/unusable in every child and nested route | E3 bounded FD check; native/refresh/PTY descriptor closure unknown |
| mounts_aliases | Fake auth and control mounts absent from worker; read-only rootfs, workspace-only writes; reject bind/namespace/alias escapes | E3 reported confinement; same-domain read-only auth bind remained readable |
| ipc_sockets | Fake keyring/agent/control Unix sockets (path and abstract where supported), queues/shared IPC; deny cross-domain reach | E3 fixture Unix socket only; no genuine privileged socket queried |
| network | Only fixture-owned local listener positive control; deny tool direct egress and credential-bearing result escape | E3 local TCP check; not every native/hosted/MCP or model output channel |
| descendant_persistence | Bounded dummy descendants from PTY/hooks/JS/subagents; cancel/death/reconnect; verify none survive or retain fake access | E3 fixed fork/reap only; arbitrary daemonization/post-turn lifetime unproved |
| same_domain_home | Worker absent fake home versus deliberately mounted fake home in auth domain; opening is enough to show exposure | E3 worker PASS / same-domain FAIL; this is a counterexample, never isolated native success |
| refresh_session_writes | Mock owner performs fake refresh/rotation; tools cannot read/write stores, influence refresh target or poison session | No authenticated refresh; no real store/account permitted; missing evidence blocks |
| cancellation_resume | Mock duplicate/late calls, unknown turn, changed build/profile/inventory, cancellation/unknown outcome and same-session resume | E2 local parser denial only; native lifecycle/tool drain remains unknown |

Future fixture probes retain existing fixed outer 15-second budget, <=2 seconds
per attempt family, <=64 KiB aggregate nonsecret output and owned-child reaping;
any wider test needs separately reviewed scope/budget. Do not run all route/probe
pairs under a single unbounded loop. A missing/unavailable denied syscall is
UNKNOWN/BLOCKED, not proof. Cancellation and child survival uncertainty fail closed;
preserve evidence, no automatic retry, cleanup, signalling unrelated processes or
resume. These are requirements for future tests, not executable instructions now.

## Offline API and verdict rules

`native_security.assess(tuple_of_SyntheticProbe, pin=BuildPin)` performs **no I/O**,
reads no host/environment/account state and has no CLI or caller-supplied client,
file path, runtime, command or real-evidence provenance. Fixed route/source pins
and historical snapshot labels are presentation, not a fresh audit. Inputs are
bounded to ten unique allowlisted mock probe kinds and exact enum verdicts; a
wrong version/hash/source/size/target, duplicate/unknown kind, raw JSON, fabricated
real provenance or unsupported shape is rejected with fixed nonsecret reason and
no partial synthetic trace. Exact-pin mismatch never assesses another build by
analogy. Output always names the fixed subject and states input_pin_matched=false.

`Verdict.PASS` means only a scripted mock reported the expected outcome. FAIL
means a mock counterexample; BLOCKED means incomplete mock conditions; NOT_RUN
means no mock observation. All rows retain real_probe=NOT_RUN. There is no GO
branch: even all-PASS mock input leaves security NO, complete mediation UNKNOWN,
activation NO-GO, native status BLOCKED/13 and all launch/resume/mutation/publication
flags false. Real operator/kernel evidence cannot be supplied through these mock
objects. Frozen types and report SHA-256 authenticate neither caller nor evidence.
The 16 KiB bounded report is reproducible; unchanged inputs yield identical
canonical SHA-256 with no clock/randomness or persistence. Missing/invalid inputs
cannot erase historical blockers. Saved JSON is not capability or authorization.

Reproduce only offline classification tests:

```sh
uv run pytest tests/test_native_security.py
```

The [baseline report](native-security-assessment.json) is the no-mock result of
`assess()`. Tests use every mock verdict and adversarial input, IO/runtime/VM/network
tripwires, unchanged gate checks and schema/pin/source correlation. They are
VERIFIED_OFFLINE, never kernel/credential mediation proof. No upstream artifact
was executed or authenticated for this milestone.

## Reconsideration and remaining decision

Keep **NO-GO** until missing fixture inputs and artifact admission/equivalence are
independently resolved, every route has exact-build mediated or immutable-disabled
proof, the proposed credential boundary passes separately authorized synthetic
negative tests under actual routes, and refresh/session/cancellation evidence is
complete. Missing one route, stale pins, untrusted provenance, ambiguous process
liveness or same-domain access is sufficient to block. No past PASS transfers to
a new SHA/profile/version, and no operator risk acceptance can be labelled an
isolation PASS. Any later auth/inference/runtime integration is another explicit
scope and review, even after a security assessment improves. No automated action,
Issue transition, merge or deployment follows from this report.
