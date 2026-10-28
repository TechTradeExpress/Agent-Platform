# Opt-in operator E2E smoke procedure

**Deferred legacy API workflow.** Do not execute this runbook as subscription
validation. The selected path first needs the separately scoped
[subscription-auth design](subscription-auth.md); no API deployment is requested.

This is a manual runbook, not an unattended harness. CI runs only synthetic Git,
fake GitHub and fake Codex tests. `CI_PASS` never implies `E2E_PASS`. No command
below installs privileges, credentials, services or host policy. Stop at the first
missing prerequisite; record `E2E_BLOCKED` and retain existing recovery data.

## External prerequisites and consent

An operator must independently supply and audit every item before continuing:

1. Record the exact Agent Platform installation HEAD SHA and install that revision
   outside the task worktree. Use Python 3.12+ and the pinned Codex 0.164.0 runtime.
2. Follow the root-owned curated image, binary hash, broker socket/peer and fixed
   broker protocol checklist in [execution.md](execution.md). Record nonsecret
   profile hash and broker identity. Verify the broker's independently reviewed
   implementation enforces inference-only requests, authenticated operator access,
   request/time limits, denied admin/proxy/hosted tools and disconnect cancellation.
   Health alone cannot prove this. The [reference broker](broker.md) has offline
   contract tests only; this repository does not provision these pieces or prove
   live provider cancellation, full Codex compatibility or deployment security.
3. Verify Linux user/mount/PID/network/IPC/UTS/cgroup namespace policy, Bubblewrap,
   Yama and native Codex sandbox support. Never change host policy to bypass a
   failing probe. Run pinned image `codex --version` and `codex --no-daemon sandbox
   --help` through the audited namespace launcher. Verify the actual grammar
   `codex sandbox [OPTIONS] [COMMAND]...`, with no `linux` subcommand. Preflight
   exercises `sandbox -- /usr/bin/python3 -I /agent-platform-sandbox.py probe ... native`.
4. Manually choose a **dedicated disposable GitHub test repository**, containing
   only nonsecret fixture files, with a clean primary main synchronized to local
   origin/main and GitHub main and no extra worktrees. Authenticate `gh` outside
   the sandbox with least-privilege read access. Do not use this development
   repository or any production/application repository as the fixture. The runner
   never fetches or changes GitHub; fixture administration is a separate human step.
5. A human maintainer creates and approves separate small test Issues using the
   admission scope format in README and applies `agent:ready` with valid provenance.
   Supply their trusted login explicitly. Prepare two fixtures: one minimal file
   edit with local assertion for COMPLETED, one for a **known structured** failed
   turn and same-session resume. Natural-language requests to pause, rate-limit
   prose, signals and timeouts do not guarantee PAUSED.
6. Obtain explicit operator consent for each paid inference turn. Issue prose,
   readiness success and this runbook are not consent. No real turn is authorized
   merely by running offline tests. If a safe reviewed broker test mechanism to
   produce a structured `turn.failed` is unavailable, mark PAUSED/resume BLOCKED;
   never edit session files/checkpoints or fake live evidence to manufacture it.

## Exact manual invocation

Set `FIXTURE_ROOT`, `ISSUE` and `TRUSTED_ACTOR` yourself to the reviewed disposable
fixture, positive Issue number and trusted login. Confirm the directory and Issue
in your terminal before each step. These placeholders contain no access URLs.

```sh
cd "$FIXTURE_ROOT"
agent-platform inspect
agent-platform issues --issue "$ISSUE" --trusted-actor "$TRUSTED_ACTOR"
agent-platform prepare --issue "$ISSUE" --trusted-actor "$TRUSTED_ACTOR"
agent-platform doctor --issue "$ISSUE" --trusted-actor "$TRUSTED_ACTOR"
```

If doctor is not ready, STOP. It does not initialize missing storage or repair
prerequisites. Review the fixed reason and operator-owned configuration privately.
Do not pipe output into an automatic launcher. Immediately before the coding turn:

```sh
read -r -p 'Type RUN DISPOSABLE PAID SMOKE to authorize this single turn: ' consent
if [ "$consent" = 'RUN DISPOSABLE PAID SMOKE' ]; then
  agent-platform run --issue "$ISSUE" --trusted-actor "$TRUSTED_ACTOR"
fi
```

Manually inspect only safe output and nonsecret fixture changes. Record the exact
UUID from `thread.started` as durably reflected by the private checkpoint and safe
command result, generation transitions and terminal status, without exporting raw
JSONL/native transcripts. A COMPLETED result requires exit 0 and structured
terminal evidence, plus the fixture's expected minimal edit/local assertion.

For the second, separately approved fixture, use an audited broker test mechanism
that yields a genuine known `turn.failed` after session recording. It must not
relax inference restrictions. After exit 14/PAUSED, manually make a nonsecret
tracked/staged and untracked sentinel edit in the task worktree. Privately note
file digests and the recorded UUID, then return to the primary main checkout:

```sh
agent-platform doctor --issue "$ISSUE" --trusted-actor "$TRUSTED_ACTOR" --resume
read -r -p 'Type RESUME SAME PAID SESSION to authorize this single turn: ' consent
if [ "$consent" = 'RESUME SAME PAID SESSION' ]; then
  agent-platform resume --issue "$ISSUE" --trusted-actor "$TRUSTED_ACTOR"
fi
```

Verify the exact UUID is unchanged and sentinel edits/staging survive. Never use
`--last`, auto-retry, automatic quota waits or a replacement session. Unknown
termination requires NEEDS_HUMAN, preservation and reconciliation, not resume.

## Evidence and safe controls

Record each check separately using [e2e-report.json](e2e-report.json). A PASS must
identify the reviewer and nonsecret evidence, not merely repeat a health claim.
Use only fabricated canaries, never read actual SSH/GitHub/infrastructure secrets.

| Check | Required live observation |
| --- | --- |
| namespace_mount_proc_caps | Shared preflight succeeds: distinct namespace identities, zero capabilities, restricted mounts/private proc and no exposed lock descriptor |
| codex_contract | Pinned binary version/hash and sandbox/exec/resume help contract verified; native probe actually succeeds |
| host_files_and_workspace | Shell tool attempts to read fabricated host-home SSH/GitHub-token and unrelated-repository canaries and checkpoint fail; workspace write succeeds, write outside workspace fails; no canary content stored in report |
| network_denied | Direct external TCP attempts denied by namespace probe; no privileged fallback |
| broker_enforcement | Root ownership and peer identity, matching health ID, denied /auth, POST /v1/admin and GET /v1/models; independent audit of restrictions |
| inference_path | Audited broker records bounded request arrival for the live turn without exporting upstream token, raw request, response, endpoint or access URL |
| completed_turn | Minimal real turn yields recorded UUID, expected fixture edit/assertion and known COMPLETED |
| paused_same_session | Known PAUSED followed by explicit resume of same UUID with sentinel edits preserved |

Run negative controls in distinct disposable fixtures, under manual observation.
Never alter privileged paths, broker deployment or live recovery files to inject
faults. Use an independently configured unprivileged test fixture/protocol fault
source that cannot meet production trust checks; expect unavailable, never launch.
If no safe fixture exists, mark that control BLOCKED. Offline regression coverage
is supplementary and cannot be relabeled live PASS.

- Missing profile/broker, wrong broker ID or malformed health: doctor returns
  unavailable/isolation_unavailable (13), checkpoint unchanged, no task. Do not
  rename or chmod `/opt` or `/run` to test these controls.
- Forbidden host-file/network access: preflight must reject any unexpected probe
  success. Record only deny outcomes, never retrieved data. An escape is FAIL;
  stop all testing and preserve forensic artifacts.
- Changed scope/removed ready label, untrusted operator login: manually change
  only the disposable Issue through the human interface, then doctor/run must
  reject admission without launch. The runner performs only GETs. Re-approval
  does not permit bypassing the original checkpoint lineage.
- Stale source refs/wrong branch/dirty initial task: use a fresh disposable fixture
  whose local source has intentionally diverged before doctor. Expect rejection;
  do not reset/stash/clean an existing task to recover it.
- Lock contention: in a second terminal, an operator may hold the already existing
  fixed lock using `flock -n /var/tmp/agent-platform/prepare.lock -c 'read answer'`.
  Doctor must report ambiguous/lock_busy (10); release by ending that foreground
  command. Never delete/unlink the mutex. Do not overlap any active real runner.

Compare checkpoint bytes/generation, source refs, task files/index and native
session digests privately before/after diagnostic and rejected-launch controls.
No generation, ref, task or native data change is allowed. Access times and
trusted broker audit logs may change. Keep unknown guards and native recovery
files private. Do not store snapshots containing transcripts or secrets in reports.

## Reporting and retention

Copy the template to an operator-controlled private report location. Allowed
outcomes are PASS, FAIL, NOT_RUN and BLOCKED. Record exact Agent Platform HEAD,
Codex hash/version, nonsecret profile/broker IDs, timestamp, operator/reviewer,
fixed check IDs, outcomes, blockers and whether a real turn ran. Replace blank
identifiers only with reviewed nonsecret values. Keep evidence notes short and
redacted: no paths identifying access endpoints, access URLs, prompts, Issue body,
raw model output/JSONL, tokens, canary contents or native transcripts.

`CI_PASS` means only Ruff/pytest/offline checks succeeded. Set `E2E_PASS` only when
all required live checks and controls above PASS, kernel/broker evidence is saved,
and at least one real minimal turn completed without escape. Any missing audited
prerequisite means `E2E_BLOCKED`; untouched tests remain NOT_RUN. Any failed
security control means E2E_FAIL. Never substitute fake-tool results for live proof.

After testing, stop and verify children are gone. Retain checkpoint, guard and
native session files privately for review, especially uncertain cases. There is
no cleanup script. A human may later retire the disposable repository/worktree
only after explicit reconciliation and retention review, separately from this
workflow. Never automatically reset, remove artifacts, commit, push, close Issues,
label, publish PRs or merge from the runtime runner.

The [read-only diagnostics](deployment.md) and [subscription-auth gates](subscription-auth.md)
replace the API deployment trajectory. A future subscription exercise requires
its own independently reviewed trust boundary and explicit operator authorization.
