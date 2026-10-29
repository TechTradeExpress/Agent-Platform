# Explicit human recovery planning — Issue #32

From the primary `main` checkout used to prepare the task:

```sh
agent-platform recovery plan --issue 42
```

This command returns a bounded, sorted JSON **investigation plan**. It performs
no recovery action, repair, replay, resume or migration. There is no `apply`
command, mutating option, arbitrary checkpoint path, session selector or remote
reference input. Read-only bounded Git identity queries are the sole subprocesses;
no repository scripts/tests, Codex, model, GitHub client, authentication, native
session store, notifier or remote operator command is invoked.

## Evidence and output

The planner uses the same locked local inspection as
[status](task-status.md), including existing version-1/version-2 checkpoint,
admission-field, scope/base, lifecycle/generation, UUID, private-storage,
source/common/worktree, branch/HEAD/registration, all-ref and guard checks.
`task_status.inspect_local` adds an internal allowlist of validated metadata;
`status` retains its existing public JSON schema and exit codes. The planner has
no second checkpoint schema, runner, Git parser or alternative storage path.

Schema version 1 contains:

- `classification` and a fixed human-readable `summary` describing the observed
  recovery case, without inferring its unrecorded cause.
- `human_reconciliation_required` and `reconciliation_state`: NEEDS_HUMAN for
  interrupted, uncertain, completed-but-unreconciled, missing, conflicting or
  unavailable evidence. Only stable READY with no guard indicates no interruption.
  These are **plan recommendations**, never changes to the recorded task phase.
- `local_evidence`: the existing status report, including recorded phase,
  checkpoint validity/generation, guard/mutex/identity observations, trusted
  recorded session UUID, known stop reason and persisted usage when available.
- `checkpoint_version`, canonical `checkpoint_sha256`, recorded `execution_id`
  and `recorded_fingerprints` for refs, isolation and runtime. Only validated,
  stable identity yields these fields. Invalid/conflicting evidence is withheld.
- `trusted_reference`, `reference_conflicts`, and `missing_or_unverified` explain
  independent comparison results and the evidence that remains unknown.
- Fixed `safe_investigation` choices and
  `prohibited_without_separate_authorization`, always with `safe_to_replay=false`,
  `resume_authorized=false` and `mutations_allowed=false`.
- `plan_sha256`: canonical SHA-256 of the plan before this field is added. It is
  a reproducibility/correlation fingerprint, not an authorization token.

Output is under **4 KiB** for supported inputs. It has no raw paths, CODEX_HOME,
Issue text, prompts, stdout/stderr, raw events/temp-file contents, secrets or
untrusted exception messages. Repeated inspection of unchanged evidence and
reference yields equivalent output; no wall-clock timestamp or random plan ID is
introduced. Invalid CLI arguments use exit 2. A clean READY plan uses exit 0;
mutex contention uses 10; all other investigation/reconciliation plans use 12.
Exit 0 means no local interruption indicated, **not permission to launch**.

## Recovery cases and conservative interpretation

| Evidence | Plan interpretation |
| --- | --- |
| STARTING | Start intent exists; whether a model turn ran is unknown |
| RUNNING, no durable terminal record | Missing stdout/terminal event, timeout, exit ambiguity or late persistence failure cannot be distinguished; do not replay |
| NEEDS_HUMAN / ambiguous stop | Preserve evidence and reconcile externally; never adopt a recent session |
| PAUSED / known failed turn | A terminal failure is recorded; investigate effects before any separately authorized exact-session resume |
| COMPLETED | Recorded completion is not exactly-once or external-effect proof; human review remains required |
| Guard with READY, PAUSED or COMPLETED | Leftover/incomplete transaction; never delete it automatically |
| Missing guard on STARTING/RUNNING | Still uncertain; absence does not prove a process stopped or a turn never ran |
| Temporary checkpoint file or partial write | Incomplete persistence; do not read/promote temporary content, rewrite the checkpoint or repeat the operation |
| Orphan guard without confirmed checkpoint | Preserve it; do not assume an unprepared task is safe to start |
| Invalid UUID/generation, bad guard, changed refs/source/worktree/admission | Block and investigate conflicting identity; do not rewrite lineage to make it match |
| Mutex busy | No checkpoint snapshot is read; contention is not proof this task or a model process is alive |
| Evidence changes during inspection | Discard partial identity; repeat investigation only after independently establishing stable conditions |

A model turn can have acted **before** a missing terminal event or crash. A
checkpoint replacement can succeed and then fail during directory sync, guard
removal or return handling. COMPLETED plus a guard is therefore not automatic
cleanup permission. No local checkpoint, matching UUID, free mutex, edited file,
recorded usage or reference hash proves that all external effects happened once.
The plan always reports `external_side_effects=unknown_not_exactly_once` and
`live_activity=unknown`; it does not probe PIDs or signal/terminate processes.

Working edits are preserved and deliberately not inventoried or hashed by this
planner. It does not judge their correctness or use their presence/absence as
execution success, failure or replay evidence. Structural worktree/ref identity
is checked by the shared helpers; content and external consequences still need
separate human investigation. A changed local source/base or unexpected worktree
can conservatively prevent inspecting historical task details.

## Recorded digests and independent reference

Local refs are compared against the recorded all-ref digest for version 2.
Runtime/isolation digests are validated recorded lineage **only**: no auth file,
transcript, native session directory or runtime image is opened/rehashed. Their
presence cannot establish current native-session consistency or credential
isolation. Missing runtime fingerprints during in-progress/ambiguous states
remain null rather than fabricated.

The CLI stays offline and does not refresh Issue labels, trusted actors, scope,
current GitHub main, remote PR state or any provider's side effects. A protected
checkpoint is the local evidence source; changing it self-consistently cannot be
detected against an absent independent original reference. These limits are
explicit in the plan, not disguised as fresh admission or safe resumability.

A separately trusted controller may call the Python API with a frozen
`RecoveryReference(admission, generation, execution_id, session_id,
checkpoint_sha256)`. This is an **exact snapshot pin**: all fields compare for
equality, not inferred ancestry from an older generation. Admission uses the
existing typed `publisher.Admission`. The controller must independently validate
and authenticate its reference; never derive it from model text, target files,
Issue prose or arbitrary JSON. Frozen types/digests are not authentication.

A pin detects otherwise valid but different scope/admission, UUID, generation or
checkpoint data. Conflicts are reported by field name; neither conflicting UUID
nor expected raw data is exposed as trusted. A busy/missing/corrupt local snapshot
cannot be compared: the reference is unverified, not a proven contradiction.
Even a matching pin establishes no live process, refreshed remote authorization,
external exactly-once outcome, safe replay or permission to repair.

## Human investigation boundary

Safe choices are to preserve edits and recovery artifacts, independently establish
process quiescence, compare durable lineage with trusted redacted receipts,
reconcile possible effects with their authoritative owners, and request a separate
human-approved intervention. These are explanatory choices, not commands executed
or new privileges granted by the planner. No raw transcript or credential access
is suggested. Original run/resume/isolation gates remain mandatory and unchanged.

Without further authorization, do not retry/resume/replay/restart; adopt another
session; signal processes; delete guards; edit/migrate checkpoints; reset, stash,
clean, checkout or discard work; write GitHub/change Issues; invoke auth/inference;
send Telegram; or weaken the blocked native runtime. There is no automatic cleanup,
checkpoint promotion, guard removal, scheduler or queue planner. Issue #33 remains
separate, and the notifier stays offline/disabled.

## Validation limits

Tests use synthetic Git/private checkpoints and the existing fake executable/
GitHub lifecycle fixtures. They crash before session recording, after session
recording, on missing/malformed terminal output, timeout, terminal write before/
after persistence, and real atomic replacement failure leaving a temporary file.
They verify stable repeated plans, valid/conflicting pins, preserved edits,
corruption, aliases, stale guards, changed refs and inspection races, contention,
no write-capable opens (apart from `/dev/null` for Git), no network/model/auth/
session-store/publisher calls and diagnostic redaction. Fake execution is not a
real Codex turn, production crash audit or external-side-effect attestation.
No recovery case is resolved automatically; unavailable or contradictory cases
remain for human reconciliation. No production/E2E readiness is claimed.
