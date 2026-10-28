# ADR 002: pinned Codex tool dispatch feasibility (Issue #20)

Decision: **SUBSCRIPTION_ISOLATION_BLOCKED**. Complete external tool mediation
has **not** been demonstrated for Codex 0.164.0. The experimental dynamic-tool
callback is a supported protocol subset; it does not replace the built-in tool
registry. No subscription execution, authentication or worker launcher is added.
This amends the research milestone in [ADR 001](subscription-architecture.md).
The safe fallback remains explicitly human-supervised development with independent
review; it is not permission to expose credentials to an untrusted repository.

## Reproducible evidence and limits

PR #19 was rechecked as actually merged, at
`ce144c665d1b195b5816cf688ddb76a051d33e2f`. Fresh fetched `origin/main`, GitHub
main and remote default HEAD agreed at that SHA before worktree creation.
The original checkout and every other worktree were preserved.

[Structured evidence](tool-dispatch-evidence.json) records the installed artifact,
source Git blob IDs, schema hashes, complete generated method inventories and
field projections. Installed `codex-cli 0.164.0` is 308,139,304 bytes, SHA-256
`b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306`.
The existing 268,435,456-byte admission cap is unchanged: this artifact is **not
admitted** to a runtime image. No build/source equivalence attestation was obtained.

Exact source pin: annotated `rust-v0.164.0` tag object
`fe3b29455488c2e189e43ad5526a107900c5e1b7`, peeled commit
`6aaac694803004a63c6f393d153c96d22521a6b9` in `openai/codex`. Tag refs were read
with bounded `git ls-remote`; public files were fetched read-only at that exact
commit. This is a **partial static audit of the tagged source**, not a claim that
all source, dependencies or the installed binary have been independently audited.
Upstream main, latest docs and an advertised version string alone are not proof.

Only the following nonsecret diagnostics ran against the installed binary:

```text
codex --version
codex --no-daemon app-server --help
codex --no-daemon app-server generate-json-schema --help
codex --no-daemon app-server generate-json-schema --out SCRATCH/stable
codex --no-daemon app-server generate-json-schema --out SCRATCH/experimental --experimental
```

All exited 0, bounded to 20 seconds and 8 KiB diagnostic output per invocation.
Each used an empty private HOME/CODEX_HOME/XDG tree and fixed PATH/locale, with
credentials, proxies and agent sockets omitted. No app-server was started. Schema
generation produced 320 stable JSON files (3,675,348 bytes) and 458 experimental
files (4,530,741 bytes). Tree digests and selected file hashes are recorded; the
two small callback schemas are retained byte-for-byte under
`tests/fixtures/codex-0.164.0/`. The full generated bundles are not vendored.
No login, login status, auth/cache reads, keyring query, account call, provider,
model turn, proxy, real credential or session-store access occurred.

## Tool coverage matrix

Two independent statuses prevent a callback contract from being mistaken for
OS isolation. **Dispatch** classifies the proposed app-server callback interface:
SUPPORTED for the explicit dynamic subset, UNSUPPORTED for audited separate
built-ins, UNKNOWN for incompletely audited routes. **Enforced boundary** asks
whether supported execution only inside an OS-confined worker or immutable
positive disablement was demonstrated. That remains UNKNOWN for **every route**.
Known configuration switches are clues, not transitive disablement proof. Any
UNKNOWN or partial result keeps subscription launch blocked.

| Route | Dispatch | Enforced boundary | Pinned evidence and remaining gap |
| --- | --- | --- | --- |
| Explicitly registered experimental dynamic function/namespace | SUPPORTED | UNKNOWN | `ThreadStartParams.dynamicTools`, `item/tool/call` and result schemas; `append_dynamic_tool_runtimes` adds separate handlers. Schema + inert fake callback tested; real callback transport/OS worker not tested. |
| Shell/unified exec/one-shot shell, `write_stdin` | UNSUPPORTED | UNKNOWN | [S1] registers internal ExecCommandHandler/WriteStdinHandler. Disabling UnifiedExec falls back to one-shot execution; ShellTool/model shell controls exist, but global immutable disablement and alternate routes are unproven. |
| Patch/apply_patch, including shell patch interception | UNSUPPORTED | UNKNOWN | [S1, S3] internal ApplyPatchHandler and intercept_apply_patch; local/remote environment and patch sandbox routes are distinct from dynamic callbacks. No complete replacement contract verified. |
| Read/grep/list, in-process filesystem and image reads | UNKNOWN | UNKNOWN | Shell can read/search/list; [S1] ViewImageHandler and MCP resources are other routes. Experimental `fs/readFile`, `fs/readDirectory`, metadata/copy/write/remove APIs and fuzzyFileSearch are separate client APIs, not proven model callbacks. Full implicit config/instruction/session file-read audit incomplete. No universal read mediation established. |
| MCP servers/resources and apps/connectors | UNSUPPORTED | UNKNOWN | [S1, S4] separate MCP runtimes/resource handlers, plus `mcpServer/tool/call`, resource and reload APIs. Per-server configuration is not a complete immutable allowlist or worker guarantee. |
| JS/code-mode host, nested calls, execute/wait | UNKNOWN | UNKNOWN | [S5] local/remote code-mode provider and nested registry dispatch; `--code-mode-host` is not a universal built-in redirection flag. CodeModeOnly still constructs a dispatcher. No proof all nested operations/processes are externally confined. |
| Background processes/jobs/queues | UNKNOWN | UNKNOWN | Exec/write_stdin and experimental backgroundTerminals, thread/queue, command/exec and process/* APIs exist. Cancellation, descendant reaping and post-turn work not demonstrated. |
| Skills/plugins, discovery/installation and instructions | UNKNOWN | UNKNOWN | [S1] plugin installation/suggestion handlers; schema skills/plugin/config APIs and user-input skill/mention variants. **ThreadStart/ResumeResponse.disabledPluginIds says it does not yet filter plugin capabilities.** No transitive disablement proof. |
| Subagents V1/V2, spawn/resume/followup | UNSUPPORTED | UNKNOWN | [S1, S6] separate agent handlers with inherited effective config and role overrides. No externally bound child inventory/credential-domain guarantee. |
| Session start/resume/fork/replay and new context window | UNKNOWN | UNKNOWN | Schemas allow resume configuration changes; experimental history/path inputs, fork, inject_items, compact/revert and new-context handlers require independent lineage and inventory audit. Same-session runtime semantics untested. |
| Pre/post tool hooks and other host hooks | UNKNOWN | UNKNOWN | [S2] conditional pre/post hooks surround internal execution, with tool-specific payloads. These are not a proven mandatory external worker protocol. Hook command spawning, all lifecycle hooks and inherited descriptors remain unaudited. |
| Hosted web search, other model/provider tools | UNKNOWN | UNKNOWN | [S1] hosted/standalone web search and model-specific tool registration. Hosted tools excluded from router inventory metrics. External mediation/positive disablement not demonstrated. |
| Permission requests, user interaction, clocks/sleep, test/control tools | UNKNOWN | UNKNOWN | [S1] feature/model-dependent registration; app-server approvals, user input, attestation and experimental currentTime/read are separate requests. Approvals are policy decisions, not execution/result substitution or isolation. |
| Remote environments, realtime/review, direct process/fs/config APIs | UNKNOWN | UNKNOWN | Generated client method inventory contains these alternate surfaces. They are not all model tools, but a supervisor must deny unnecessary client APIs and audit model reachability. Remote shell support is not whole-process credential separation. |
| Implicit persistence, auth refresh, inherited fds/proc/IPC/network | UNKNOWN | UNKNOWN | Not tools that dynamic callbacks necessarily observe. No proof against credential-store writes, parent-memory access, fd leakage, session poisoning or refresh persistence. Never forward account/chatgptAuthTokens/refresh to a worker. |


Pinned source references (all at the commit above):

- [S1: registry construction](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-rs/core/src/tools/spec_plan.rs): shell 1235–1265, resources 1270–1285, other tools 1350–1435, agents through 1567, dynamic 1572–1601; hosted search around 698–715.
- [S2: router](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-rs/core/src/tools/router.rs#L359) dispatches to the [internal registry](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-rs/core/src/tools/registry.rs#L701); conditional hooks and internal handler invocation appear at 701–790. Dynamic calls have a [separate pending-response path](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-rs/core/src/tools/handlers/dynamic.rs#L190).
- [S3: apply_patch](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-rs/core/src/tools/handlers/apply_patch.rs#L302), including interception at 435 and execution routing at 476.
- [S4: MCP resources](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-rs/core/src/tools/handlers/mcp_resource.rs#L37) and separate MCP tool handler (blob recorded in evidence).
- [S5: code mode](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-rs/core/src/tools/code_mode/mod.rs#L130), including execute/wait/interrupt and nested dispatch at 336 onward.
- [S6: multi-agent config inheritance](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-rs/core/src/tools/handlers/multi_agents.rs#L1).

These are counterexamples to equating dynamic tools with universal interception,
not proof that no supported upstream solution can ever exist. Feature/model
catalogs, managed requirements, provider capabilities, role overrides, MCP reload,
plugins, filesystem/config sources and resume/fork history can change inventory.
A fixed initial dynamic list, model instructions, approvals, or native sandbox
flags alone cannot enforce the requested credential boundary.

## Protocol transcript: schema evidence, not a live session

`tests/fixtures/codex-0.164.0/transcript.json` is **fabricated and never sent**.
Its request shapes use generated ClientRequest, ClientNotification and parameter
contracts. It records this proposed sequence, without fabricating real server
responses or pretending that a session was created:

1. `initialize` with clientInfo and experimentalApi opt-in, then `initialized`.
   The opt-in exposes experimental fields; it is not a security negotiation.
2. `thread/start` with one synthetic function dynamicTools entry. It is absent
   from the stable ThreadStartParams schema. A real response must be validated
   and its actual thread identity bound before any turn; no such response tested.
3. `turn/start` with a fabricated threadId and text input. **Do not send this**:
   a real turn could authenticate and infer. Real turn ID comes from a validated
   server response; this fixture's IDs have no session authority.
4. Hypothetical `item/tool/call` request: id plus params arguments, callId,
   threadId, tool, turnId and optional namespace. Arguments are arbitrary JSON
   in upstream schema; our proof restricts them to one literal fabricated canary.
   Response uses the same request id and `result: {contentItems, success}` with
   fixed inputText content. No `jsonrpc` marker is specified by the generated
   app-server JSONRPCRequest schema. This proof rejects extra envelope fields,
   including optional trace, as outside its explicitly supported subset.
5. Approval callbacks (`item/commandExecution/requestApproval`, fileChange,
   permissions, legacy approvals) are **not** tool execution callbacks. The proof
   rejects them and all unknown/auth/interaction callbacks, never approves them.
6. `turn/interrupt` binds threadId and turnId in schema. Locally close the proof
   on cancellation, disconnect or isolation loss and reject subsequent callbacks.
   This tests local denial only: server cancellation, queue draining, child
   termination and cleanup acknowledgements were **not** exercised.
7. `thread/resume` requires threadId; optional configuration can alter behavior.
   Schema recognition is not same-session continuity proof. This proof cannot
   resume, fork, adopt history, reset replay tracking or reload a tool inventory.
   Existing Agent Platform explicit UUID/checkpoint resume behavior is unchanged.

No live transport, initialization handshake, tool-list acknowledgement, server
cancellation, authentication refresh or actual same-session resume was observed.
A production adapter needs supported version/schema and immutable inventory
binding on start **and** resume, rather than trusting strings from a server/model.

## Offline proof and threat handling

`agent_platform.tool_dispatch_probe.CallbackProof` is a standalone pure parser,
not wired to the CLI, runtime, checkpoint, host lock or auth. It has no transport,
filesystem, executor or network facility. Its fixture inputs pin version, callback
schema hash, inventory digest and thread/turn IDs. One inert synthetic function
can return only a constant acknowledgment; it cannot run shell/code or echo data.
A successful proof is never an isolation or launch attestation.

Frames are bounded to 8 KiB, aggregate input to 32 KiB and calls to 16. Duplicate
keys, malformed UTF-8/JSON, nonfinite numbers, excessive nesting, invalid IDs,
unknown fields/tools/namespaces, instructions posing as authority, nonliteral
arguments, wrong session/turn, stale inventory and replayed request/call IDs deny.
Any error permanently closes that proof, reports one generic error and retains
no executable payload. Disconnect/cancellation/isolation loss are modeled by a
local close, with no automatic retry or resume. Paths to synthetic auth/proc/fds
are rejected data, never opened. Fabricated credential canaries and intercepted
I/O/spawn/socket functions test absence of parser side effects, not worker safety.

The trust model and attacks from ADR 001 still apply: a future worker must have
no auth/native-session/control-plane mounts, host network/IPC, parent memory,
ptrace or inherited credential/lock fds, including across tool descendants,
symlinks, crash and refresh. Trusted Codex itself must not perform unmediated
model-driven reads/writes in its credential domain. Unknown schema/tool,
inventory changes, lost isolation or protocol disconnect must stop before any
operation and preserve NEEDS_HUMAN semantics. This parser does not establish
those OS or lifecycle properties and does not replace launch-time validation.

## Evidence levels and next decision

| Level | Actual result |
| --- | --- |
| Exact installed version/help/schema generation | PASS, nonsecret offline diagnostics only |
| Pinned source | Partial static audit; separate built-in and dynamic paths identified |
| Fabricated protocol/canary regression tests | Offline parser validation only; see PR's exact test results |
| Real Linux kernel/worker canaries | **BLOCKED/NOT_RUN**: no already configured, reviewed immutable credential-free runtime fixture; no elevated probe attempted |
| Account/subscription/authenticated E2E | **LIVE_NOT_RUN**, authentication NOT_INSPECTED |
| Audited deployment/production readiness | **NOT_DEMONSTRATED** |

The upstream gap is an audited, supported, exhaustive tool-policy/dispatch
contract that disables or redirects every model-invoked operation *before* it
can access the trusted auth process's resources, including in-process reads,
patching, nested code/MCP/agents, hooks and restored sessions. Its inventory must
be immutable/attestable and unknown or newly introduced routes must fail closed.
Dynamic callbacks and conditional approvals alone do not supply that contract.

Smallest safe next milestone: obtain an upstream-supported complete dispatch or
managed disablement specification for an exact build, independently audit its
full transitive inventory and schema, then repeat a no-account transport proof
and unprivileged immutable-worker canary suite. Stop if any route remains unknown.
Before even proposing a version bump, audit new built-ins/hosted tools, feature
and config precedence, every nested/extension route, auth/session refresh,
resume/fork/replay, hook lifecycle, cancellation, binary provenance and artifact
size. Reproduce schema diffs and negative tests; independently review the new
pin and runtime packaging. No automatic update, cap increase, API fallback,
auth.json mount, OAuth forwarding or privileged proxy is an acceptable shortcut.
Only a later independently reviewed milestone could authorize operator login
and live subscription evidence. CI success for this spike cannot do so.
