# CP-04/1 — offline independent reviewer handoff eligibility

Issue #92. **OFFLINE_IMPLEMENTATION / NO LIVE GO**. This pure Python API evaluates
fabricated trusted-caller observations. It does not run a reviewer, collect GitHub
evidence, authenticate a worker/App/human, or publish a review. It has no CLI,
transport, filesystem, clock, subprocess, model, worker messaging or scheduling
adapter. No shared publisher, evidence, assignment, runtime, packaging or CI
interface is modified.

## Contract and use

`agent_platform.worker_review_handoff.assess(handoff, observations, now=...)`
returns a frozen/slotted `Result`. Inputs are frozen/slotted dataclasses, schema
version 1. `Handoff` carries the trusted job/assignment, existing PR ID, existing
`github_evidence.Policy`/`TargetProject`, both worker identities, complete retained
contributor lineage, source/CI digests and issuance/expiry. Each contributor binds
its historical job, exact revision, worker/agent/session/context/worktree and
`review_comment.AppIdentity`/`InstallationIdentity`. Current implementation must
appear at the exact candidate HEAD in that history. Old contributors remain even
when jobs, Apps or installations rotate.

`Observations` is a separate, independently qualified **synthetic trusted-caller**
input. It binds the full handoff digest, target project digest, source/CI digests,
actual PR numeric ID, canonical/head/base repository identities, base branch,
HEAD/base/merge, ordered merge parents,
actual author and reviewer App/bot/installation/account, reviewer context,
contributor/review/thread/check/Issue inventories, exact counts, observation times,
completeness and isolation assertions. The independent source assertion includes
canonical commit/diff/Issue retrieval and the native single closing association;
the complete links inventory represents agreement with the sole closing reference.
Source and CI digests correlate those independently qualified facts, not an
implementer's summary. `final_statuses_successful` asserts complete independently
qualified final legacy-status observations; these cannot substitute for App checks.

The caller must already hold both trusted pins and independently qualified fixture
facts. Never deserialize candidate/model/Issue data into this trusted role. There
is intentionally no JSON parser or generic client/callback. Unknown constructor
fields raise TypeError; mappings, subclasses, wrong nested types, unknown schema
versions, bool-as-int, malformed IDs, NaN/infinity and duplicate facts fail closed.
Construction alone does not validate eligibility: call `assess`. `digest` is only a
canonical correlation helper, not validation or authentication.

A minimal inert typed usage, with separately constructed fabricated inputs, is:

```python
from agent_platform.worker_review_handoff import Handoff, Observations, assess


def fixture_advice(pins: Handoff, facts: Observations, synthetic_now: int):
    return assess(pins, facts, now=synthetic_now)
```

This is neither an instruction for a live agent nor a downstream approval receipt.
The tests contain complete deterministic examples for both role directions on
separate candidates. No worker01 session, transcript or worktree is consulted.

## Gates and bounds

- Reuse `CodexAssignment.for_project`, `Policy`, `TargetProject`, `Check`, App,
  installation and principal validation. A missing project context is explicitly
  unsupported. This requires a real existing-PR context supplied synthetically;
  it never fabricates a pre-PR project or a #49 reviewed Receipt. The assignment's
  coding App is the actual author; reviewer/project publication context must bind
  the distinct reviewer App, bot, installation and target account.
- The reviewer must differ from **every historical contributor** on worker, agent,
  session, context, worktree, App ID/slug, bot ID/case-insensitive login and
  installation ID. Both-worker contribution blocks either worker's review.
  Role/App/installation rotation never clears lineage. Reviewer edits, transcript
  access or a shared writable worktree block. Fresh worktree/session, separate
  context/auth storage and independent canonical source retrieval are mandatory
  trusted assertions. Hostnames alone provide no isolation guarantee.
- Require open Draft PR, exactly one same-repository linked open Issue, unchanged
  immutable HEAD/current base/current merge, parents exactly `[base, head]`, full
  contributor/review/thread/CI/link inventories and no unresolved findings,
  unresolved threads, blocking reviews or new security blockers.
- Required `checks` and `lifecycle` must each appear exactly once for direct HEAD
  and current base-bound merge, with pinned App ID/slug, unique run IDs, completed
  success and actual checkout SHA equal to that run's exact commit. Names or
  run-head claims alone never establish checkout identity. Extra/duplicate runs,
  missing/pending/failed/skipped checks, wrong Apps or changed pins block. The
  trusted caller must first resolve any run-selection ambiguity independently;
  this API does not select a latest green run.
- Canonical ASCII JSON handoff descriptor maximum: **8192 bytes**, including all
  retained contributors. Separate observations maximum: **65536 bytes**. Maximum
  **128 total observation records** across contributors, linked Issues, checks,
  reviews and threads; every individual collection is also capped at 128. A
  descriptor may hit its byte ceiling before the record ceiling. Nothing is
  truncated, evicted or silently widened. Full inventories must match exact
  declared counts; partial pagination or instability blocks.
- Caller supplies integer time, issuance/expiry window at most **300 seconds**,
  current time before assignment and handoff expiry; all source/CI/snapshot/run
  observations must be nonfuture and at most **300 seconds** old. Runs precede CI
  observation; source/CI observations precede the aggregate snapshot. Integers
  representing time are bounded to `[0, 2**63)`. No wall clock is read.

## Output and evidence limits

| Status | Meaning |
| --- | --- |
| `ELIGIBLE_OFFLINE_FIXTURE` | Complete consistent qualified synthetic fixture satisfies the exclusion and evidence rules; no live authority |
| `INSUFFICIENT_EVIDENCE` | Missing observations, unqualified/candidate-origin or unsupported live provenance, or missing project context |
| `BLOCKED` | Malformed, conflicting, stale, partial, oversized or unsafe evidence |

Results contain only fixed redacted reasons, schema version, and on eligibility
validated handoff/observation digests and exact HEAD/base/merge pins. No raw text,
identities, conversations, paths, API bodies, exception messages or credentials
are emitted. Every result sets `review_authorized`, `comment_authorized`,
`approve_authorized`, `ready_authorized`, `issue_closure_authorized`,
`merge_authorized`, `publish_authorized`, `launch_allowed` and `resume_authorized`
to false. Hashes and booleans do not authenticate their source. Supplying
`qualified=True` or a provenance string from a model creates no trust boundary.

Live App/bot attribution, contributor-origin completeness/continuity, independent
canonical retrieval/remote check receipts and actual checkout provenance are
**NOT_IMPLEMENTED / BLOCKED**. New `CheckRun` and context facts express fixture
assertions for fields not proven by existing evidence contracts; there is no live
adapter supporting those fields. Existing #49 collection does not itself attest
actual checkout SHAs or model-context separation. No private helper, fabricated
prepublication PASS or source AP-SM/2 review is converted into a product Receipt.

Fresh-worktree/session and independent context/auth storage are also **synthetic
assertions**, not kernel/host/session-store inspection or proof of independent
reasoning. Distinct AI sessions are not independent humans, and different bot IDs
are not authenticated human approval. Genuine worker identities, external custody,
anti-rollback lineage and reviewer isolation need separately approved assurance.
Every live input provenance remains unsupported; successful offline fixtures do
not relax that boundary.

[CP-02](github-app-publisher-contract.md), [AP-SM/2](solo-maintainer-policy.md),
[#49](github-evidence.md), [#59](review-comment.md),
[#62](target-project-policy.md) and AP-CH/1 remain unchanged. Source acceptance
still requires the separately human-requested ChatGPT exact-HEAD review and all
CI/security gates; this Codex implementation cannot accept itself. COMMENT,
Ready and Issue completion require their separate existing human delegation;
merge remains human-only. No actual model review, COMMENT, live App connection,
credential, writer, scheduler or worker adapter follows. #73 remains live NO-GO;
native/subscription isolation and public legacy quarantine remain at exit 13,
without API-billing fallback.

## Validation

Run `uv run ruff check .`, `uv run pytest` and `git diff --check` in the dedicated
worktree. Tests cover rotating roles, self/both-worker review, historical App
rotation, shared context/worktree, wrong author/App/installation/project,
HEAD/base/merge drift and parents, both CI checkout/App/freshness paths, Issue
linkage, incomplete inventories, unresolved findings/threads, exact record/time
limits, descriptor overflow, duplicates, invalid types/versions, fixed redaction,
immutability and side-effect denial. Offline PASS is not live or E2E PASS.

### worker02 local validation record

Validated on Python **3.13.5**, pytest **9.1.1**, base
`f5aee4c608cf48d291d6b3472d0e0ba1d90af8b7`:

- `uv run ruff check .`: PASS.
- CP-04 tests: **124 passed**.
- Final full `uv run pytest`: **2682 passed, 2 failed, 1 skipped**, exit 1.
- `git diff --check` and staged whitespace check: PASS.

Both failures also reproduce when using the unchanged base main source/tests
with the same interpreter, independently of CP-04:

1. `test_native_artifact.py::test_file_mutation_after_digest_read_is_detected`:
   expected `file_changed`, observed `invalid_load`.
2. `test_notifications.py::test_bot_request_exact_contract_and_no_token`:
   expected `ValueError`, observed Python 3.13 `dataclasses.replace` `TypeError`
   for an `init=False` field.

These are reported baseline/runtime blockers to a fully green suite, not ignored
or converted to PASS. No shared native artifact/notification code, tests, Python
requirements or CI were changed. Only Python 3.13.5 was available locally; no
alternate interpreter or host prerequisites were provisioned. A first CP-04-only
run also found a fixture's invalid uppercase `[BOT]` suffix; the fixture now
preserves the existing Principal contract's `[bot]` suffix while testing
case-insensitive login exclusion. Final CP-04 tests pass. Live checks remain
NOT_RUN, and this record supplies no execution or publication authority.
