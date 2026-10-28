# Trusted Publisher: offline plan validation — Issue #30

This milestone adds a Python API, `agent_platform.publisher.plan`, for inspecting
one completed task's proposed changes. It has **no publishing operation, CLI
command, GitHub client, token input or authentication**. Success is
`INSPECTED_PUBLISH_CANDIDATE`, always `publish_authorized=false`. It is not
permission to commit, push or create a PR. Runtime `run`/`resume` and their coding
child still have no GitHub-write authority. Supervised contributor delivery is
separate; see [development.md](development.md).

## Trust and data flow

The future trusted control plane supplies three explicit inputs:

1. The canonical primary source checkout path, outside the coding worktree.
2. An immutable `Admission`, constructed from the result of the existing
   `prepare.approved` after operator-selected trusted actors and stable Issue/
   label-provenance checks. Its exact fields are canonical repository ID/name,
   Issue ID/number, approved scope digest/revision, admission digest and base SHA.
3. Immutable `TestEvidence` from an independently trusted test collector, binding
   the canonical checkpoint digest, full worktree digest, **exact** expected
   `FileChange` inventory, and three PASS receipts in order: `ruff`, `pytest`,
   `diff_check`. Each receipt has a SHA-256 artifact digest. Raw logs are not read.

These are **trusted caller assertions**, not model/file inputs or cryptographic
attestations. No deserializer loads admission, expected changes, test receipts,
PR settings or authority from the repository, Issue prose, Codex messages or a
saved plan. A frozen dataclass is not an authentication boundary; code executing
inside the trusted Python process could fabricate one. The test-collector and
admission delivery/authenticity boundary requires separate review before real
publication. Do not generate trusted test receipts from a model's claimed PASS.

Conceptual integration (trusted controller only; not a runtime entrypoint):

```python
from agent_platform.publisher import Admission, plan

# approved_snapshot comes from existing trusted admission, not target JSON.
# trusted_test_evidence comes from the separate trusted test collector.
candidate = plan(source_root, Admission(**approved_snapshot), trusted_test_evidence)
report = candidate.diagnostic()  # bounded, redacted, JSON-ready
assert candidate.publish_authorized is False
```

The API performs no GitHub calls. It compares the supplied admitted snapshot to
the existing checkpoint; it does not claim live Issue/label/default-branch
freshness. A changed *newly admitted* scope/revision/identity invalidates the old
checkpoint. Offline code cannot detect GitHub changes absent a refreshed trusted
snapshot. Any future publisher must independently refresh admission/remote state
and revalidate immediately before each separately authorized operation.

## Immutable schema, version 1

`Admission`, `FileChange`, `TestCheck`, `TestEvidence` and `PublishPlan` are frozen,
slotted dataclasses. Inventories and receipts are tuples, never mutable lists.
Schema values are checked before accepting a candidate. `PublishPlan` captures:

| Field group | Binding |
| --- | --- |
| `admission` | Exact typed repository/Issue identity, scope revision/digest, admission digest and base SHA |
| `source_root`, `common_dir`, `worktree`, `branch` | Reverified canonical local identity; branch is checkpoint-derived `agent/issue-N` |
| `checkpoint_generation`, `checkpoint_sha256` | Completed version-2 lineage and canonical SHA-256 of the entire nonsecret record |
| `session_id`, `execution_id`, `refs_sha256`, `common_sha256` | Exact recorded UUIDs, all Git refs and observed Git control metadata |
| `changes`, `inventory_sha256`, `tree_sha256` | Sorted expected/actual changes, modes, base/index Git blob IDs, working sizes/SHA-256 and full working-tree digest |
| `evidence_sha256` | Digest of the exact checkpoint/tree-bound trusted test receipts |
| `idempotency_key` | SHA-256 of canonical sorted compact JSON for the complete plan with this key empty |
| Fixed fields | `schema_version=1`, `terminal_state=COMPLETED`, `execution_guard=ABSENT`, `base_branch=main`, `draft=true`, `publish_authorized=false` |

Git SHA-1 object IDs are repository lineage identifiers, not artifact integrity
proof. Working files and evidence use streaming SHA-256; the trusted evidence
also binds all working-file content, including files outside the changed list.
The PR title is fixed to `Issue #N: proposed changes`, and body to a fixed template
with exactly `Closes #N` and the no-authorization statement. No arbitrary URL,
remote, reviewer, label, command, token, permission or publisher destination is a
plan input. The same trusted inputs and unchanged observed state yield the same
idempotency key; changed content, index state, checkpoint or receipts invalidate
that identity. This is a correlation key, not a transaction or remote duplicate
prevention mechanism.

## Validation and conservative limits

The API takes the **existing** fixed host mutex via `state.host_lock(create=False)`;
missing or busy locks block, and no lock directory/file is initialized. The lock
is held through all checks; pathname/inode/metadata replacement is rejected.
Only a version-2 `COMPLETED` / `TURN_COMPLETED` / `completed` checkpoint with exact
attempt/generation lineage, UUIDs, pinned CLI version, usage and recorded runtime
fingerprints is accepted. Execution guards, checkpoint temporary files, private
storage ambiguity and checkpoint replacement/drift block. It never opens native
session directories or auth stores; recorded runtime hashes are lineage only,
not fresh credential/runtime inspection or isolation attestation.

Existing source/admission/checkpoint/worktree/ref primitives are reused:
`prepare.source_snapshot`, `prepare.checkpoint_record`, `prepare.confirm_identity`,
`execution.refs`, `state.load_checkpoint`, the fixed lock and bounded read-only
Git wrapper. The primary `main`, local `origin/main` and admitted base must agree;
worktree HEAD remains exactly at that base with its recorded task branch. Only
the registered primary and task worktree are allowed, matching the existing
runtime contract. Extra refs, commits, worktrees, altered common directory,
submodules, unsupported config/index flags or dirty source checkouts block.

Source/common paths are checked for aliases and unsafe ownership/modes. Git
control files must be regular single-link files, with no symlinks, set-ID,
unexpected writer lock files or changing metadata. In a private 0700 common root,
inner group-write bits cannot grant traversal; otherwise group/world-write bits
are rejected. This checks local visibility, not proof that host administrators or
other same-UID processes are stopped. The coding process must independently be
prevented from modifying the common directory, checkpoint, collector or publisher.

Descriptor-relative traversal and nested-mount rejection reuse
`runtime_manifest.walk` / `mounts`. The task tree rejects symlinks, hardlinks,
special files, foreign ownership, group/world write, set-ID and private/ambiguous
paths. Only the root linked-worktree `.git` pointer is allowed as Git metadata.
Files are opened read-only with `O_NOFOLLOW|O_NONBLOCK`; descriptor/path identity,
size and timestamps are compared around streaming reads. Two complete inventories
must agree, including directory/file fingerprints. Git metadata, refs, source,
guard and checkpoint are rechecked before returning. No state is repaired.

NUL-delimited status is cross-checked against base/index blob IDs and file bytes.
Staged, unstaged, mixed, additions, deletions and untracked changes are explicit.
Ignored artifacts, renames/copies, conflicts, staged-deleted-and-recreated paths,
unsupported encodings or normalization differences are refused for reconciliation,
never guessed or silently omitted. A path is ASCII, relative, <=256 characters,
with no traversal/private components. The API intentionally supports a narrow,
small-change subset, not every valid Git repository or filename.

Each Git query uses existing sanitized environment, fixed argument structure,
disabled hooks/fsmonitor/external filters, no shell/network/lazy fetch, five-second
timeout and <=256 KiB output. Tree walks are <=4,096 entries/depth 32, <=128 changed
files, <=8 MiB/file, <=32 MiB total; reads are <=64 KiB. Each content walk has a
30-second cooperative deadline. Filesystem calls may themselves stall; no hard
wall-clock claim is made. Expected receipts cannot expand these limits.

`diagnose(source_root, admission, evidence)` returns a JSON-ready result under
1 KiB with safe identity, counts and digests, or fixed `BLOCKED` refusal codes.
It omits local paths, filenames, Issue/model text, logs, raw remotes and exceptions.
The full in-memory plan is trusted internal data; do not dump it as a diagnostic.
No imported runtime execution or isolation preflight is invoked.

## Evidence and next gate

Tests use existing fake GitHub endpoints through real admission validation and
synthetic Git repositories/checkpoints; terminal completion and test receipts
are fabricated fixtures. They exercise identity/scope/base mismatches, staged/
unstaged/untracked inventory, refs, dirty guards, contention, malicious model
metadata, aliases/mounts, malformed status, missing/stale evidence and races.
No real publication, credentials, inference, kernel confinement or live E2E is
proven. An inspected plan expires as evidence when any bound state changes; it
is not a reservation after the lock is released.

Actual GitHub App credentials, credential isolation, independently authenticated
receipt collection, remote revalidation, least-privilege write authority and
safe commit/push/Draft-PR transactions require a **separate maintainer-approved
Issue**. No token may enter Codex or its worktree. No automatic publication,
retry, scheduler, Telegram notification (#37), operator console (#38), permission
change or service deployment is implemented here. Native execution, subscription,
artifact admission and Linux confinement gates remain unchanged.
