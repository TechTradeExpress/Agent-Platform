# PKG-17 release continuity fixture

The stable key is `TechTradeExpress/Agent-Platform/0.1.0-8/amd64` for Control
and Worker together. This module has no command-line or packaging entrypoint.
Production generation still calls the unconditional PKG-13 refusal (exit 13).

## Exercise and reconcile

Use reviewed code, a disposable pre-existing private directory (0700) on a
local filesystem, and PKG-16's `collect(source, historical_directory)` when
the two verified historical archives are available. PKG-16 checks the original
archive bytes, source commit/tree and recipe; the ledger validates the record
shapes and binds the three canonical observations by SHA-256. Source inventory
covers the complete observed Git tree, including all recipe paths. Both final
artifact hash slots are reserved and must remain empty in PKG-17. An
`Observation` supplied to Python can also be fabricated, so the ledger records
`UNVERIFIED_CALLER_FIXTURE` even when the caller ran the machine observer.

A test supervisor binds a generation-zero `FixtureCheckpoint` to the stable
key, `fixture_slot_sha256(root)` and `fixture_bundle_sha256(observation)`.
With that input, `record_fixture(root, observation, generation=1,
checkpoint=checkpoint)` serializes one proposal. The fixed slot is claimed
exclusively and synced in its parent. It contains an exclusive UNKNOWN intent
and, only after that intent is synced, an exclusive receipt that binds the
intent hash. Each file is flushed and fsynced, and each directory entry is
synced. The fixture root must already be durably provisioned by the supervisor.
The intent and receipt bind the root path and filesystem identity and the
actual slot directory's identity. Cooperating processes take a nonblocking
directory lock. Files and directories are opened without following symlinks;
the read path rechecks file and directory identities and metadata.

The test supervisor can separately retain a generation-one checkpoint with the
observed receipt SHA-256. `reconcile(root, observation, checkpoint=checkpoint)`
checks the complete records without writing or repairing anything. If a write
fails or the worker exits, preserve the whole slot even if empty. Reconciliation
requires matching generation-one evidence. An identical prior attempt still
cannot acquire the occupied fixture slot. A stale or conflicting checkpoint,
path substitution, partial record or lost receipt leaves UNKNOWN. A current
checkpoint retained separately also detects rollback to a clean directory.

A successful fixture report has the following values:

| Field | Value |
| --- | --- |
| `status` | `BLOCKED` |
| `history` | `UNKNOWN` |
| `history_authenticated` | `false` |
| `custody`, `operator_authority` | `NOT_CONFIGURED` |
| `local_integrity` | `LOCAL_FSYNC_COMPLETED` on successful write, `LOCAL_RECORDS_MATCH` on matching reconciliation |
| all action flags | `false` |

A filesystem sync failure reports UNKNOWN. A match only compares local bytes
against the modeled checkpoint and cannot certify storage behavior after power
loss. This fixture has no trusted clock or independent storage. Rolling back
both the local slots and the supplied checkpoint can recreate an apparently
virgin fixture. Advisory locks and owner-only paths do not protect against the
owner, root, or administrative storage rollback. Never treat a fixture
checkpoint or receipt as evidence that no earlier attempt or freeze exists.

## PKG-18 handoff

Select an independently protected custody domain, reviewed operator identity
mapping and authorization channel in an explicit operator security decision.
Implement the `ProtectedCustody` port separately, with fresh challenge binding,
a stable release-key lookup and a compare-and-set that durably records UNKNOWN
before any generation attempt. Bind the exact source, environment, fixed
output slot, prior receipt and generation. Verify live rollback and
interruption behavior under distinct real principals before admission.
`CustodyQuery` and `CustodyEvidence` define an inert handoff shape; this
implementation neither calls the port nor authenticates the data.

Only after authenticated admission has been reviewed should PKG-18 integrate
the two-role final generation path. Retain UNKNOWN on interruption. Independent
final-byte review, a separate human publication decision and immutable
external freeze remain separate gates. PKG-17 is SOURCE_ONLY / NO_RELEASE /
HOST_NOT_RUN. LIVE_NO_GO, Gate #73, PUB-02 and subscription exit 13 remain in force.
