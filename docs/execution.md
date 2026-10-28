# Guarded execution (MVP.2b)

**Legacy API-backed contract; deployment is deferred.** The selected subscription
path requires the separately reviewed [authentication design](subscription-auth.md).
The interfaces below are preserved, not promoted as subscription readiness.

`run` and `resume` are explicit operator commands, invoked from the same clean
primary `main` repository root used for `prepare`:

```sh
agent-platform run --issue 42 --trusted-actor maintainer-login
agent-platform resume --issue 42 --trusted-actor maintainer-login
```

They never prepare a task, select an Issue, choose a recent session, or retry a
turn automatically. `run` requires an existing version-1 READY checkpoint and a
clean task worktree exactly at the verified base. `resume` requires a version-2
PAUSED checkpoint and its exact UUID. COMPLETED is terminal; STARTING, RUNNING,
NEEDS_HUMAN, missing identity, orphan checkpoint files or execution guards require
human reconciliation. Use the separate `doctor` diagnostic below to check readiness without a coding turn.

Both commands reauthenticate the exact open Issue, current labels and applicable
ready-label actor, and compare scope digest/revision, immutable repository ID,
main/origin/main/GitHub base and canonical source/common/worktree identities.
The operator allowlist remains the trusted authorization boundary. No automatic
TTL is inferred from prose: removing/reapplying labels, changing scope/revision,
or removing actor trust invalidates the prepared lineage. A prior `issues` or
`prepare` result is insufficient to launch.

First start requires a clean checkout; resume deliberately permits tracked,
untracked and staged coding edits while preserving HEAD at base and the exact
task branch. A digest of **all** Git refs rejects unexpected refs, and the only
registered worktrees must remain the primary checkout and this task. Flags that
hide index changes, external hardlinks, special files and nested mounts are
rejected. Neither command resets, stashes, cleans, fetches, deletes worktrees,
changes refs, commits, pushes, publishes PRs or writes GitHub. Keep unrelated Git
writers stopped while the task is running; the host mutex cannot stop them.
First start rejects ignored artifacts too. Do not place credentials or other
secrets inside the approved worktree before or between turns: files intentionally
provided inside the writable task directory are task data, not hidden host data.

## Required, externally installed security profile

Execution supports one Linux profile, not a configurable arbitrary launcher.
**The CLI never installs/provisions the profile, broker, namespaces, identities or
credentials.** Without all prerequisites and successful probes it returns exit
13, `isolation_unavailable`, with no execution checkpoint migration or coding
turn. Filesystem permissions and environment filtering alone are insufficient.

A maintainer must separately supply and audit these trusted components:

- `/usr/bin/bwrap`, owned by root, not group/world writable, supporting user,
  mount, PID, network, IPC, UTS and cgroup namespaces, `--die-with-parent` and
  `--sync-fd`. Unprivileged user namespaces and Yama ptrace restrictions >= 1
  must be available. No sudo, privileged fallback or host security changes occur.
  Setuid/setgid executables and insecure runtime-path ancestors are rejected.
- `/opt/agent-platform/codex-0.164.0/rootfs`: a minimal, credential-free runtime
  image containing `/usr/bin/codex` **0.164.0**, `/usr/bin/python3`, `/bin/sh`,
  their libraries and any offline toolchain needed by the task. Its directories
  and regular files must be root-owned and not group/world writable. This narrow
  profile rejects symlinks and special files throughout the image (50,000 entries
  maximum), external hardlinks and nested mounts; it never binds the host
  `/usr`, `/home`, `/run` or root filesystem.
  The image must not contain credentials, host repositories, deployment tools
  with credentials, user configuration, or privileged services.
- A root-owned `profile.json` alongside `rootfs`, <= 4 KiB, containing
  `{"version":1,"codex_version":"0.164.0","codex_sha256":"<binary SHA-256>","broker_id":"<64-character deployment identity>"}`.
  The exact binary hash and version are checked; changing the profile/helper
  fingerprint invalidates resume.
- An **already provisioned, audited credential-separating inference broker** at
  `/run/agent-platform/inference.sock`. Its parent must be root-owned and not
  group/world writable; its socket must be root-owned, not world accessible,
  and grant the operator connection permission (for example through its group).
  SO_PEERCRED must identify the serving peer as UID 0. The separately runnable
  [reference broker](broker.md) provides offline-tested protocol code, not an
  audited deployment or installation workflow. The runner never starts it.

The broker is part of the trusted computing base, alongside the kernel,
Bubblewrap, curated image and pinned Codex. It must keep inference credentials
outside every sandbox and never return credentials or raw credential-bearing
upstream errors. It must accept only bounded, authenticated inference forwarding
for this operator, enforce per-turn/time/request limits, forbid hosted network
or infrastructure tools, storage/background jobs, arbitrary upstream hosts,
admin/credential endpoints and generic HTTP CONNECT/proxying, and cancel upstream
work when the sandbox disconnects. It must not grant GitHub or SSH access.
**A generic forwarding proxy does not satisfy this contract.** No host auth file,
API key, SSH agent, GitHub token or infrastructure secret is copied into Codex.

The root-owned broker's local HTTP contract is:

- `GET /agent-platform/health`: HTTP 200 with exactly
  `{"protocol":1,"broker_id":"<matching profile ID>","inference_only":true,"credentials_exposed":false,"network_tools":false}`.
- `POST /v1/responses`: OpenAI Responses-compatible inference/SSE, with credentials
  added outside the sandbox, limits and the restrictions above enforced by the
  broker itself. Sandbox code can reach this socket, so the broker must enforce
  these restrictions independently of the relay.
- Other methods/paths return 403. Preflight specifically checks `/auth`,
  `POST /v1/admin` and `GET /v1/models` without sending any inference request.

Root ownership/peer checks establish the administrative trust boundary; the
health response is not an attestation that can replace auditing the broker.
The image, broker policy and kernel must be maintained by a trusted operator.
No positive deployment claim follows from fake-tool tests alone.

## What preflight and execution enforce

Preflight uses the **same namespace profile** as execution, with ephemeral
workspace/runtime tmpfs mounts so probes do not modify task files. It checks
namespace identities differ from the host, effective capabilities are zero,
control-plane installation/source/checkpoint/lock and secret paths are invisible,
no lock descriptor is exposed to sandbox processes, direct TCP egress fails,
and Codex's native Linux sandbox denies runtime-home writes while allowing
workspace edits. The pinned CLI version is also checked without a coding turn.
A missing native sandbox or failed probe is fatal; no profile is weakened.
The runner installation itself must be outside the writable task worktree.

The installed `codex-cli 0.164.0` help declares
`codex sandbox [OPTIONS] [COMMAND]... [COMMAND]`; there is no `linux` subcommand.
The native preflight therefore uses
`codex --no-daemon -c sandbox_mode="workspace-write" sandbox -- /usr/bin/python3 -I /agent-platform-sandbox.py probe <policy-json> native`.
The OS-specific namespace profile remains outside this command. A failing native
command or an unverified probe still returns `isolation_unavailable`.

At execution, only the prepared worktree is mounted writable as `/workspace`;
its `.git` pointer is read-only and the host Git common directory is not mounted.
Codex uses `--skip-git-repo-check` because Git operations requiring that hidden
common directory are intentionally unavailable inside the sandbox. `/tmp` and
`/dev` are private; `/proc` contains only namespace processes. The curated runtime
is read-only. A task-specific fresh Codex home is mounted at `/codex-home`, with
native sandbox writes restricted to `/workspace`; there are no host auth files.

A bounded namespace-local HTTP relay exposes only Responses inference to Codex
through the separate broker socket. Codex uses the fixed custom provider with
no credential environment key, no WebSocket transport and no automatic HTTP/SSE
retries. Host credentials and proxies are not inherited. Issue prose cannot
alter command arguments, mounts, approvals, access rights or environment.
The current Issue body goes through controlled stdin as JSON inside a randomly
delimited untrusted-data block after trusted runner instructions.

The Codex argument contract was checked against the installed 0.164.0 help:
`codex --no-daemon --ask-for-approval never ... exec --json --sandbox workspace-write ... -`;
resume adds `resume <checkpoint UUID> -` after the exec flags. There is never
`--last`, ephemeral session storage, a shell, unrestricted access or broadened
approval policy. See [official non-interactive documentation](https://learn.chatgpt.com/docs/non-interactive-mode).

## Durable state and limits

Version-1 prepare checkpoints remain unchanged until a successful preflight and
fresh admission. Migration to version 2 occurs atomically at explicit launch:

```text
v1 READY (generation 2)
  -> v2 STARTING (durable RUN intent, generation 3, attempt 1)
  -> RUNNING (exact thread.started UUID durably recorded, generation 4)
  -> COMPLETED or PAUSED (generation 5)
PAUSED -> STARTING (RESUME, attempt +1) -> RUNNING (same UUID) -> terminal
any unknown/uncertain termination -> NEEDS_HUMAN
```

A small, nonsecret, exclusive `.execution-guard` file is fsynced before migration.
It survives parent crashes and checkpoint failures. Only its creating invocation
removes it after reaping the child and durably recording a known terminal state;
leftover guards always block launch. The fixed host flock remains held across
admission, all transitions and the full child lifetime. Its descriptor is held
by the trusted Bubblewrap supervisor (`--sync-fd`), not exposed to model tools,
so a parent-death race cannot release exclusivity while the child remains live.
Bubblewrap's parent-death/PID namespace boundary and process-group termination
bound the child tree. SIGINT/SIGTERM preserve recovery data, not a resumable guess.

Version 2 adds pinned runtime/profile identity, execution lineage, all-ref and
native runtime-file digests, a minimal stop reason and token usage. The exact
UUID comes only from `thread.started.thread_id`. A different or duplicate UUID,
including on resume, is an error. Native Codex session files needed for resume
remain in the private task-specific runtime directory under
`~/.local/share/agent-platform/codex-sessions/<repo-id>/issue-N/<execution-id>`;
they may contain task transcripts. They are never copied into checkpoints.
Their digest must match before resume. `prepare` refuses execution-state
checkpoints without rewriting them.

A turn has a 300-second deadline; stdout JSONL lines are <= 64 KiB, combined
streams <= 8 MiB, stderr <= 64 KiB, and <= 10,000 events. Prompt stdin is <=
128 KiB. All streams require valid UTF-8. Raw stderr, errors, commands, messages,
file contents and arbitrary item payloads are discarded. Checkpoints stay <=
16 KiB and preserve the existing atomic write/fsync/replace/expected-record rules.

A valid `turn.completed` plus exit 0 is COMPLETED. A valid `turn.failed`, exact
session ID and exit 0/1 after the child is stopped is PAUSED. Quota/rate-limit
**prose is not parsed as authority**: inspect the recorded status, resolve the
account issue separately, and manually request `resume` only for PAUSED.
Missing terminal events, malformed JSON, stream overflow, timeouts, signals,
unexpected exit codes or uncertain checkpoint writes mean NEEDS_HUMAN. There is
no automatic sleep, retry, quota reset wait, alternative session or fresh start.

Outputs are bounded JSON. Existing usage/inspection/admission/lock/Git/storage
exit statuses are preserved. Exit 0 is completed, 14 is known PAUSED, 13 is
isolation unavailable, and 12 is uncertain execution/checkpoint state. No raw
provider diagnostics or secrets are printed. A successful run does not publish
changes or authorize a later run with different scope.

For recovery, stop and verify all relevant processes are gone before reviewing
checkpoint, guard, native session files, refs and worktrees. Keep forensic data;
there is no automatic cleanup, reset, session adoption or repair command.
Do not edit a checkpoint to bypass an unknown state. Reconcile manually under
maintainer review. Host/profile setup and production kernel/broker validation
remain separate operator responsibilities; this implementation uses only fake
Codex/GitHub and synthetic repositories in its automated acceptance tests.


## Readiness diagnostics (MVP.2c)

From the prepared fixture's primary main checkout, invoke:

```sh
agent-platform doctor --issue 42 --trusted-actor maintainer-login
agent-platform doctor --issue 42 --trusted-actor maintainer-login --resume
```

The default requires version-1 READY; `--resume` explicitly requires version-2
PAUSED and its recorded session/runtime lineage, preserving coding edits. Both
use the exact execution admission, host mutex, source/ref/worktree/checkpoint
validation and `Profile.preflight`, including a final admission/source re-read.
They return before guard creation, checkpoint migration, runtime-directory
creation or a coding turn. Probes use ephemeral namespace mounts. Doctor opens
only the existing fixed mutex, without creating it or its parent. An absent
mutex fails closed; `prepare` is the existing explicit initialization path.
Doctor never calls prepare, repairs state, writes native files or changes GitHub.
Read-only filesystem inspection may update filesystem access times; it does not
promise bit-for-bit filesystem metadata immutability or zero broker audit logs.

The JSON contract contains only `status` and `reason`:

| Status | Reason | Exit |
| --- | --- | --- |
| ready | checks_passed | 0 |
| unavailable | isolation_unavailable | 13 |
| unavailable | admission_unavailable | 8 |
| unavailable | local_unavailable | 12 |
| ambiguous | invalid_target | 7 |
| ambiguous | admission_rejected | 9 |
| ambiguous | lock_busy | 10 |
| ambiguous | source_mismatch | 11 |
| ambiguous | checkpoint_or_task_invalid | 12 |
| ambiguous | unsafe_storage | underlying storage error (normally 7) |

Only exit 0 means all checks passed at that instant. Reasons are deliberately
coarse and never contain stderr, paths, Issue text or provider diagnostics.
Invalid operator arguments use argparse's existing usage errors (exit 2).
Readiness is neither a launch reservation nor an attestation of the audited
broker's internals. Run/resume always repeat validation. Offline CI cannot prove
kernel isolation or inference deployment security. Follow [the manual E2E
procedure](e2e.md) to collect distinct live evidence.

## Static diagnostics and subscription direction

[Read-only diagnostics](deployment.md) now exclude API deployment/rehearsal.
[Subscription-auth gates](subscription-auth.md) describe the selected product
path and why the existing custom-provider/empty-home runner does not implement
it. Existing runtime security checks remain unchanged. API broker deployment is
deferred; do not mount authentication caches or forward OAuth tokens as a bypass.
