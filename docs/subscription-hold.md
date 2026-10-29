# Subscription usage facts and explicit operator HOLD — Issue #34

`agent_platform.subscription_hold` is an offline API for safe usage presentation
and a separate, explicit human HOLD record. It does not execute Codex, inspect
accounts or acquire quota. Native execution and `agent-platform subscription`
remain `SUBSCRIPTION_ISOLATION_BLOCKED` (exit 13). No runtime gate is changed.
There is no new CLI command, scheduler, signal, automatic retry or resume.

## What the supported evidence proves

The existing pinned Codex 0.164.0 `codex.Events` contract accepts an exact session
UUID, turn lifecycle and successful-turn token counters. It discards arbitrary
item/error payloads. `turn.failed` establishes a failed turn, not its cause.
Neither it nor stderr, model prose, a synthetic `usage_limit_reached` string,
Issue descriptions or extra JSON fields establishes subscription exhaustion.
The older presentation prototype in `subscription.py` is unchanged.

`LimitEvidence` and `Usage` are frozen typed values. `summarize` consumes only an
explicit tuple of synthetic JSONL bytes, bounded to 256 events, 64 KiB per event
and 1 MiB total. It reuses the existing parser, exact expected UUID and terminal
exit validation, with a non-writing session callback. Malformed, duplicate-key,
unrecognized, oversized, interrupted, inconsistent-usage or wrong-session data
discards partial facts. No stream file, stdout, stderr or native session store is
opened. Ordinary successful counts have classification `unknown`; a confirmed
failure has `turn_failed_unclassified`. Synthetic provenance remains synthetic.

Persisted usage is reported only from a validated local checkpoint, with
`usage_provenance=persisted_checkpoint`. These are historical turn counters,
never remaining quota, plan entitlement or an account balance. Cached input must
not exceed total input. This extra presentation check changes no checkpoint
schema or existing parser/runner behavior. PAUSED with recorded `turn_failed`
also reports `turn_failed_unclassified`, never a verified quota diagnosis.

There is **no vetted structured subscription-limit source** in this supported
adapter contract. `verified_limit` is reserved for future independently reviewed
evidence and is not constructible/emitted here. Remaining quota stays unknown,
`reset_at` stays null, and account identity stays uninspected. No reset date,
limit amount, login/account attribution or OAuth/token inspection is inferred.

## Direct trusted operator decision

`HoldDecision` is an immutable **trusted in-process human input**, like existing
Publisher admission/review receipts. Its reason is one of `HoldReason`:

- `operator_pause`
- `subscription_uncertainty`
- `review_required`

No free text, error text, model output, file loader, expiration, timer or release
flag is accepted. Enum values alone do not authenticate a human. Only the
separately trusted controller may construct decisions following a direct
operator action; never deserialize these from a task repository, event, Issue,
Telegram message or saved plan. The existing typed `publisher.Admission` pins
repository ID/name, Issue ID/number, scope/revision/provenance and base SHA.

For an existing task, the decision must also include an exact, independently
trusted `recovery.RecoveryReference` (same admission, generation, execution UUID,
recorded session UUID and full checkpoint digest). Reuse the trusted local
observation/reference boundary documented in [recovery.md](recovery.md); do not
obtain authority from a model's claimed reference. An absent/mismatched reference
cannot silently adopt an existing checkpoint. A pre-preparation HOLD can use
`checkpoint=None` only when inspection confirms no checkpoint or orphan artifact
and the sole registered worktree is the verified clean primary main checkout.

Conceptual trusted-controller API:

```python
from agent_platform.subscription_hold import HoldDecision, HoldReason, report, set_hold

# admission and exact_reference are independent trusted inputs, never target JSON.
decision = HoldDecision(admission, HoldReason.OPERATOR_PAUSE, exact_reference)
response, code = set_hold(canonical_primary_root, decision)  # explicit human action
status, code = report(canonical_primary_root, admission)    # strictly read-only
assert status["launch_allowed"] is status["resume_authorized"] is False
```

## Persistence and failure behavior

The only durable write is the nonsecret separate record at
`~/.local/state/agent-platform-holds/<repository-id>/issue-N.json`, using the
existing trusted `prepare.HOME`, not HOME/CODEX_HOME overrides. The record binds
the exact admission, source identity digest and optional full checkpoint
reference. It records schema version 1, fixed kind OPERATOR_HOLD, allowlisted
reason and a deterministic SHA-256 idempotency key over canonical record fields.
It stores no clock values, account/auth paths, tokens, prompts, logs or raw errors.
A digest is a consistency/correlation check, not a signature or human identity.

All operations reuse the existing **non-creating fixed host mutex**, private
0700 directory/0600 single-link file validation and read-only source/status/
guard/worktree/ref checks. No native session/auth files are accessed. The same
lock covers all observations, writes and stable rereads. A busy or missing mutex
blocks; the HOLD layer does not provision it. Admission/base/source, checkpoint,
session, guard or lock drift fails closed. RUNNING remains recorded local state,
never current process activity. A free lock is not process-quiescence proof.

Only `set_hold` may create the separate private HOLD parents and call the shared
atomic storage writer. Task checkpoint, guard, session and Git metadata are never
written. Identical duplicate decisions return `already_recorded` without a
rewrite. A conflicting reason/reference or changed lineage preserves the old
record and requires human reconciliation. No hold is overwritten to follow a
new session or generation automatically.

The shared writer uses exclusive no-follow temporary creation, flush/fsync,
atomic replacement and directory fsync. Reads are bounded by the existing 16 KiB
storage limit and 128 entries per repository directory, with metadata rereads.
Symlinks, hardlinks, unsafe owners/modes, corruption, duplicate keys, orphan
temporary files and interrupted persistence block without repair/removal. Failure
before replacement leaves the temporary artifact for a human. Failure after
replacement is reported as uncertain; subsequent validated inspection can retain
the observed HOLD. It never interprets uncertain durability as release.

Missing HOLD state is **unknown, not released**, even if it was never created.
The read-only report does not initialize it. Only a separately approved future
release decision plus fresh validation could end a HOLD; this API has no release
operation. No absent file, clock or completed turn grants permission to continue.
This layer is not wired into the existing runner or queue as a new gate: those
contracts remain unchanged, and native execution is already unconditionally
blocked. Any future activation must independently integrate mandatory HOLD checks
without treating a missing/invalid record as permission.

## Report, evidence and limitations

Reports are at most 4 KiB, with fixed keys and allowlisted diagnostics. They show
observed phase, unknown live activity, HOLD state/reason, classification/provenance,
persisted turn usage, missing evidence and manual intervention requirements.
Only an independently validated explicit HOLD produces `classification=operator_hold`
and `display_status=WAITING`; PAUSED and NEEDS_HUMAN are never rewritten into HOLD.
Missing/corrupt/conflicting state is NEEDS_HUMAN. `launch_allowed=false` and
`resume_authorized=false` are unconditional. No raw exceptions, paths, UUIDs,
JSONL, secrets or provider prose are returned. Identical inspection is stable and
read-only. Code 0 means observed HOLD, 10 mutex contention, 12 blocked/unknown.
It never means execution, retry, recovery or release authorization.

Offline tests use synthetic Codex events and existing fake-GitHub/local-state
fixtures. They exercise successful usage, spoofed limit payloads, malformed and
interrupted streams, every phase, exact operator lineage, duplicate/conflicting
HOLD, atomic-write failures, corruption/aliases/permissions, contention, bounded
redaction and no network/model/auth access. A fake-executable integration test
injects interruption during durable session recording: checkpoint readers and
HOLD must remain blocked with guard/temporary evidence preserved. The existing
real-signal fake-adapter regression also checks that an interrupted atomic write
is an unresolved recovery outcome, with no subsequent launch or state cleanup.
Offline PASS does not establish real
account quota, live authentication, audited storage separation or E2E safety.
Same-UID or privileged compromise of the trusted controller/store is outside
this receipt model; no cryptographic human attestation is claimed. Independent
review and separately approved release/integration design remain necessary.
Telegram console #38, notifications, inference and runtime activation are absent.
