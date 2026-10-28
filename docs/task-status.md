# Read-only local task status — Issue #31

From the primary `main` checkout previously used to prepare a task:

```sh
agent-platform status --issue 42
```

The command returns one sorted, bounded JSON object. It is completely offline:
no GitHub client, account authentication, model, Codex process, isolation probe,
native session-file inspection or publisher operation is invoked. Existing
**bounded read-only Git queries are the sole subprocess exception** to the
Issue's no-spawn objective. This reuses existing repository/worktree identity
checks instead of adding a second Git parser. It does not launch a task/runner,
run repository code or use `gh`. No Git writes, fetch or lazy object retrieval
are authorized; unsupported repository layouts/configuration fail closed.

Example READY snapshot (generation is the checkpoint's persisted generation):

```json
{
  "schema_version": 1,
  "issue": 42,
  "status": "recorded",
  "reason": "local_checkpoint_only",
  "recorded_state": "READY",
  "checkpoint_validity": "valid",
  "generation": 2,
  "execution_guard": "absent",
  "host_lock": "free",
  "identity": "verified",
  "session_id": null,
  "stop_reason": null,
  "usage": null,
  "live_activity": "unknown",
  "remote_admission": "not_checked",
  "launch_allowed": false
}
```

## Interpretation

`recorded_state` is durable local evidence, **never current process activity**.
READY, STARTING, RUNNING, PAUSED, NEEDS_HUMAN and COMPLETED are accepted only under
the existing version-1/version-2 checkpoint schema and known lifecycle. A recorded
RUNNING checkpoint does not establish that Codex, Bubblewrap or any child is
alive. `live_activity` remains `unknown` in every result; no PID/process scan,
credential read, account/quota query or reset-time guess is performed.

`checkpoint_validity=valid` means the private file has a supported schema and
matches the requested Issue, local recorded admission and source identity.
`identity=verified` additionally means worktree/common directory, exact branch,
HEAD/base, registrations and (for version 2) all-ref fingerprint were checked.
An interrupted version-1 prepare intent can have a valid NEEDS_HUMAN checkpoint
and missing/unconfirmed worktree; that returns blocked/conflicting identity,
without a session identity. No current GitHub admission is claimed. Stored scope/
admission digests, revision and numeric repository/Issue IDs are syntax/lineage
checked with existing admission helpers; labels/actors are not refreshed offline.

`session_id` is emitted only after checkpoint and task identity validation and
stable re-reads. It is the exact persisted UUID, never a recent/discovered session.
`stop_reason` is restricted to known persisted values (`completed`, `turn_failed`,
`ambiguous`), and `usage` to the existing validated token counters for COMPLETED.
None of these is live subscription usage, quota authority, test PASS or permission
to run, resume or publish. No native/auth path or session contents are opened.

`host_lock=free` means status acquired the existing fixed mutex during inspection.
It is released on return; this is not a future reservation or proof no external
writer/process exists. `busy` prevents checkpoint inspection: state/session/
generation remain unknown rather than reading a concurrent transaction. Missing,
unsafe or inaccessible locks are reported without initializing or repairing them.

The guard is inspected read-only as a private single-link 37-byte execution UUID
record. A leftover guard, invalid marker, mismatch, STARTING/RUNNING with a free
lock, or NEEDS_HUMAN remains blocked/ambiguous and needs human reconciliation.
A COMPLETED checkpoint with a remaining guard is still a **recorded** completion,
not recovery success; the command does not remove the guard. Missing guards on
in-progress records never make a process live or a turn resumable.

| Result | Meaning | Exit |
| --- | --- | --- |
| `recorded` | Supported stable READY/PAUSED/COMPLETED local record, guard absent | 0 |
| `missing` | No matching checkpoint; no preparation performed | 12 |
| `blocked` | Known interrupted state/guard, or unconfirmed worktree identity | 12 |
| `ambiguous` | Corrupt, stale, conflicting, changed or unverifiable local state | 12 |
| `unavailable` | Lock absent/unsafe/inaccessible | 12 |
| `unavailable`, `lock_busy` | Existing mutex held by another invocation | 10 |
| Usage error | Missing/nonpositive/out-of-range Issue argument | 2 |

All schema keys are present on every result. Unverified values are null/unknown;
errors never include raw exception text, Git stderr, Issue text, prompts, paths,
raw JSONL or credentials. Diagnostics are under 1 KiB for supported inputs.

## Checks and limits

The operator's current primary repository is checked using existing inspection,
`prepare.source_snapshot` and `prepare.confirm_identity`; status is conservative
when local main/origin/main diverge, HEAD/base move, extra worktrees appear or
recorded refs change. It is not a historical checkpoint browser, readiness
probe or alternative admission mechanism. Target coding edits are preserved;
status neither hashes their content nor runs their tests. Run/resume and any
future publisher must independently repeat their own stronger checks.

Repository ID discovery is local, under the fixed private state parent, at most
128 numeric repository directories and one <=16 KiB Issue checkpoint per entry.
No arbitrary root/store/session path flag is exposed. Duplicate matching records,
symlink/permission/ownership/hardlink ambiguity, unfinished checkpoint temporary
files and orphan guards fail closed rather than silently select or clean state.
An unrelated malformed Issue-N record can conservatively block discovery; the
command does not guess its repository or skip damaged recovery evidence.

The existing mutex is opened read-only with `create=False`; checkpoints and guards
use bounded read-only `O_NOFOLLOW`/nonblocking access and before/after identity/
timestamp checks. A final checkpoint/guard/lock/source re-read rejects observed
changes. Existing Git calls have sanitized environments, fixed arguments, disabled
hooks/filters for content queries, five-second deadlines and <=256 KiB output.
Filesystem calls may stall; this is not a hard wall-clock deadline. Filesystem
access times and transient flock state may change; no file content, permissions,
checkpoint generation, refs, guard or worktree is written or repaired.

Tests prepare synthetic Git/checkpoint fixtures with fake GitHub admission, then
assert status has no network/auth/model/publisher calls or write-capable opens
(except the subprocess library's `/dev/null` handle). They exercise all phases,
resume generations, interrupted prepare, corruption, aliases, guard conflicts,
contention, orphan recovery files, changed snapshots, stale local identity and
redaction. This is offline evidence only. Native/subscription execution remains
blocked; live inference, credential isolation and production E2E are untested.
Telegram (#37), notifications, scheduling and automatic recovery are out of scope.
