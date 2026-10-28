# Native Codex adapter and supervised offline dry-run (Issue #24)

**A — stock Codex CLI SELECTED. Subscription runtime remains disabled.**
Agent Platform is the orchestrator, not a replacement model agent. B/SIWC
app-server and C/custom Responses agent are deferred/not approved. [ADR 003](subscription-transport.md)
records the binding decision while preserving earlier research. The operator's
ChatGPT subscription is the intended funding path; no separately billed API or
OAuth-forwarding workaround is introduced.

PR #23 was rechecked merged at `4676beae0176da57f19e1d1aad005617879ff687`;
GitHub main/default HEAD and fetched origin/main matched before creating
`feature/issue-24-native-codex` in the dedicated Issue #24 worktree. Existing
checkouts and ignored/local work were preserved.

## Implemented seam, not an enabled backend

`native_codex.execute` first calls an unconditional rejecting gate (exit-code 13
reason `subscription_isolation_blocked`). There is no enabling CLI flag, config,
environment variable, model boolean or executable-path option. The subscription
CLI continues returning its existing blocked JSON without calling this adapter.
Tests explicitly monkeypatch both the gate and isolation launcher; that is not a
supported runtime authorization mechanism.

The small internal `execution._execute` seam accepts a trusted argument builder.
Legacy `execution.execute` supplies its original builder; native supplies fixed
native arguments. Admission and fresh Issue validation, source/worktree/ref
identity, host mutex, durable guard/checkpoints, `codex.Events`, private session
digest and bounded `process.stream_jsonl` remain shared. No parallel lifecycle,
checkpoint schema, custom LLM loop, publisher or retry scheduler was introduced.

Native arguments select the built-in OpenAI provider and force ChatGPT login;
provider retry settings are zero. Fixed exec flags request JSONL, workspace-write,
no additional writable roots/network, config/rules suppression and controlled
stdin. Task prose is untrusted JSON inside the existing delimited prompt, never
argv or executable selection. Nothing logs arbitrary events/stderr or embeds
prompts/credentials in checkpoints. The child environment is the existing fixed
PATH/locale map; production isolation must supply its reviewed runtime context.

The installed `codex-cli 0.164.0` version, exec help and resume help were re-read
with empty temporary HOME/CODEX_HOME/XDG, no tokens/proxies, ten-second timeouts
and <=16 KiB captured output per diagnostic; all exited 0. No auth/status query
or coding turn ran. Pinned help supports parent exec options before `resume`,
explicit UUID and final `-` for stdin. The adapter uses that ordering, never
`--last`, session names, forks, ephemeral sessions or unsafe sandbox flags.
The exact 0.164.0 source [config schema](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-rs/core/config.schema.json)
(blob `cce71e46c17084a76d7d7ad7945145f3d4d1a256`) includes forced_login_method's
chatgpt/api enum. This establishes parser/config compatibility clues, not actual
authentication, enforcement or source-to-binary equivalence.
[Current official noninteractive docs](https://learn.chatgpt.com/docs/non-interactive-mode)
corroborate JSONL and explicit resume; current guidance is not pinned live proof.

The existing isolation profile is still the **legacy credential-free API-broker
profile**. It is not a native subscription profile. Removing the gate alone is
not an implementation plan: a separately reviewed native profile, account/session
binding, runtime admission and supported credential lifecycle remain required.
Synthetic version-2 checkpoints prove reuse of current mechanics only; no real API
session is adopted/migrated into a subscription session by this increment.

## Lifecycle and offline evidence

- Durable STARTING intent/guard precedes child launch; exact canonical v4/v7 UUID
  from thread.started is persisted synchronously as RUNNING before more events.
- Confirmed turn.completed + valid usage + exit 0 yields COMPLETED. Known
  turn.failed + exit 0/1 yields PAUSED (command exit 14). Only explicit resume of
  that exact recorded UUID is possible after fresh admission and session digest
  validation; legitimate tracked/staged/untracked edits survive.
- Malformed, wrong UUID, trailing/truncated events, limit breaches, uncertain
  exits, interruption or checkpoint failure preserve recovery guard/data and
  require NEEDS_HUMAN. Repeating start/resume does not reconcile or rerun them.
- Shared bounds: 300 seconds, prompt 128 KiB, JSONL line 64 KiB, combined stream
  8 MiB, stderr 64 KiB, 10,000 parsed events. Shell is disabled; subprocess group
  is terminated/reaped even after terminal output. Tests shorten deadlines.
- A turn.failed message is not a quota API. Manual hold may change presentation;
  no inferred reset time, automatic retry, scheduled wait or auto-resume exists.

Reproduce only the synthetic executable slice:

```sh
uv run pytest tests/test_native_codex.py
```

Temporary executable fixtures actually receive argv/stdin, emit JSONL and edit
only synthetic repositories. Fake GitHub traverses real admission with fixed GET
requests; tests tripwire other parent-side subprocesses. Tests check exact argv,
credential-environment exclusion, command-injection data remaining inert,
checkpoint/session/guard behavior, lock contention, private session-file tamper,
edit preservation and cancellation. Closing an inheritable non-lock fd is tested;
this is **not** denial of parent proc/memory. Fake isolation can access its test
files: these tests claim orchestration behavior, not OS or token isolation.
Runtime GitHub writes remain forbidden; only the separately authorized developer
publishes this Draft PR.

## Host containment and the remaining credential risk

A future dedicated nonprivileged disposable VM/OS boundary should deny the CLI
and tools homelab filesystem/network access: no host home, Docker socket, SSH or
GitHub keys/agents, infrastructure secrets, shared clipboard/mounts or privileged
services. Give it only a disposable approved worktree, reviewed runtime and
minimal inference egress. A future trusted publisher has separate credentials;
Codex/tools never receive them or authority to commit/push/publish.

**A VM around the entire CLI does not hide CODEX_HOME inside that VM from its
tools.** Same-domain shell/file operations may read or change auth/session stores,
inspect the authenticated parent or inherited fds, or persist access. Native
workspace-write, chmod 0700, fixed environment and approval prompts do not prove
otherwise. Read-capable tools can leak tokens through output/model requests even
when arbitrary egress is denied. ADR 001/002's unresolved routes still matter.

Future actual login requires independently reviewed OS enforcement or a separate,
explicit maintainer risk decision documenting the narrowly scoped disposable
environment, assets exposed and containment limits. Risk acceptance is not an
isolation PASS or safe unattended-login claim; it does not weaken today's runner
checks or enable this gate. Any runtime/profile activation still needs a separate
implementation/review and operator authorization. Do not copy real auth caches,
forward OAuth, enable API fallback or improvise a privileged proxy.

## Operator-only opt-in Linux canary runbook: no account

Current result: **BLOCKED / NOT_RUN**. No already configured, reviewed immutable
native fixture is available. No kernel probe or host modification was attempted.
The legacy doctor/broker health contract cannot attest native token isolation.

1. Obtain independent review of an **already available unprivileged** disposable
   VM/user-namespace fixture, its exact source/runtime hashes and mount/proc/fd/
   network manifest. It must contain no account, tokens or production repository.
   If unavailable, stop and report BLOCKED; never install root services, change
   permissions/caps, disable namespaces or retry outside containment.
2. Operator explicitly opts into one no-account run. Inside that disposable
   fixture, prepare only fabricated CODEX_HOME auth/session markers, fake host
   home/SSH/GitHub/control-plane sentinels and a worktree write sentinel. Use new
   fixture paths, no overwrites of existing work. Do not query login/status,
   credential services, account APIs or model endpoints.
3. Reviewed fixed probes must run under the **actual proposed tool boundary**,
   not an unrelated sandbox. Bound the outer run to 15 seconds, individual file/
   process/network probes to two seconds and output to 64 KiB. Use the pinned
   native sandbox grammar (`codex sandbox -- <fixed reviewed probe>`, no linux
   subcommand) only inside an admitted fixture. No coding/model turn is needed.
4. Model-invoked-style shell/file/process probes attempt reads and writes to each
   fabricated credential/session and external sentinel, traversal/symlink escape,
   parent proc/memory/fds and outside-worktree writes. Require denial, while the
   worktree sentinel edit succeeds. Test direct networking only against a
   fixture-controlled local listener, never a public service. Verify namespace/
   capability identities, no host sockets and descendant reaping on cancellation.
5. Inspect only result codes/digests, never canary contents/raw commands/stderr.
   Any credential-readable path, descriptor, network path or unknown result is
   FAIL/BLOCKED; retain bounded recovery evidence and do not authenticate. A
   native sandbox that allows fake-home reads demonstrates the unresolved risk,
   not permission to ignore it. Repeat after separately reviewed profile changes;
   no automatic fallback, cleanup or promotion follows from a failed probe.

Report source/artifact/profile hashes, fixed caps, fixture provenance and each
negative check as PASS/FAIL/UNKNOWN. Separate **offline subprocess PASS**, **real
kernel NOT_RUN/PASS/FAIL**, **credential-isolation audit** and **live E2E NOT_RUN**.
A Linux test using arbitrary shell probes is model-invoked-style evidence, not
proof every Codex internal read/tool route obeys that boundary. Passing canaries
cannot resolve untested paths or independently authorize an account-consuming turn.

## Artifact admission and next step

Installed 0.164.0 is **308,139,304 bytes**, SHA-256
`b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306`, exceeding
the unchanged **268,435,456-byte (256 MiB)** runtime cap. This Issue does not raise
the cap, switch binaries or claim admission. The small fake executable proves
none of production artifact acceptance, authentication, refresh or kernel safety.

Next operator options: independently review packaging/admission for the pinned
artifact and a disposable nonsecret native Linux fixture, then perform the bounded
canary plan if safely available. Resolve or explicitly assess same-domain token
risk under the separate authority above before proposing login. Native Codex stays
the engine throughout; a blocker is not authorization for a custom agent.

## Validation for this increment

- `uv run ruff check .`: PASS.
- `uv run pytest`: **621 passed in 71.35s**, comprising 592 baseline tests and
  29 new native adapter tests; the focused new suite also passed independently.
- `git diff --check`: PASS.
- Direct `uv run agent-platform subscription`: **exit 13**, launch_allowed=false,
  SUBSCRIPTION_ISOLATION_BLOCKED, authentication NOT_INSPECTED, LIVE_NOT_RUN.
- Installed binary size/hash were rechecked without credential access; no runtime
  cap or pinned binary changed. The SHA-pinned Draft PR records CI separately.

These are offline subprocess/state and nonsecret diagnostic results. Kernel
canaries BLOCKED/NOT_RUN; real auth/refresh, subscription inference and real
same-session native resume E2E_NOT_RUN. No deployment-readiness claim follows.

Issue #26 implements the separate [opt-in executable synthetic canary helper](native-canary.md).
It does not remove this adapter's block or admit the pinned artifact. Its actual
BLOCKED/kernel-NOT_RUN observations are distinct from this Issue #24 offline suite.
