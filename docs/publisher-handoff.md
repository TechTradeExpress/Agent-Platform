# PUB-01 source-only publisher handoff — AP-PH/1

Issue #104 adds byte-only untrusted intake and a **synthetic-only** existing-Draft
update transaction. There is no HTTP client, credential loader, executable Git,
filesystem intake, listener, service, scheduler, CLI or runtime integration.
`LIVE_NO_GO`, Gate #73, `HOST_NOT_RUN`, native subscription isolation and public
legacy exit 13 remain unchanged. PR #103 is only a proposed future pilot target;
no publication, credential, App or host action is authorized by this library.

## Proposal: reconcile CP-02 custody with worker-local publishers

[CP-02](github-app-publisher-contract.md) currently proposes control01 custody.
Its independent host, authority and governance gates remain binding. This
**alternative architecture proposal** models operator-selected separately
privileged publishers on each worker VM, not a deployed replacement for CP-02.
A publisher UID is a separate unprivileged principal, not root or a privilege
escalation path. The operator-reported accounts/Apps/grants and unconfined state
in #104 are testimony, not independent admission or effective enforcement proof.
No code trusts those numeric IDs, names or reported protections as defaults.

The worker emits inert candidate bytes. A separately reviewed trusted receiver
would accept a bounded message into a publisher-owned spool; neither principal
traverses the other's checkout. The publisher must not read worker `.git/HEAD`,
hooks, config, filters or files, and no chmod/chgrp/ACL broadening solves intake.
The worker gets no publisher files, socket/signer capability, token, key, generic
Git helper or authenticated network client. Typed ingress must remain separate
from custody, exact-payload human admission and the exclusive anchored journal.
No receiver, spool writer, cross-UID channel or custody composition is implemented.

Same-VM separation requires independent negative proof: cross-UID proc/memory/
ptrace/process_vm/FD/env/coredump denial in both directions; immutable code,
private state, authenticated peers, effective AppArmor attachment and systemd
restrictions after exec/reboot; resource bounds, fixed egress and a protected
continuity anchor. Same-UID 0700, env filtering, LoadCredential copies, App names,
local locks and a VM boundary alone cannot prove those properties. In particular,
LoadCredential is readable by its unit UID and cannot isolate a signer from
untrusted code in that unit. An unconfined publisher is a live blocker.

`publisher-handoff-policy-candidates.json` contains **inert requirement strings**,
DESIGN_ONLY and installable=false, not unit/profile syntax. Tests verify its
closed exact version/requirements and absence from Debian archives. No packaging,
profile loading, host probing or service activation follows from these strings.

## Bounded untrusted byte artifact

`publisher_handoff.intake(data, policy, now=...)` accepts exactly `bytes` <=1 MiB.
No Path, file descriptor, bundle filename, archive, pickle, command, callable,
URL, symlink/hardlink metadata or worktree root is accepted. There is no filesystem
adapter to follow a physical link or execute a bundle. Actual `git bundle`/pack
and repository-level intake are unsupported. A future file receiver must prove
no-follow/exclusive ownership, single-link regular-file identity, complete bounded
reads and stable metadata; this API does not trust caller-supplied stat assertions
as a substitute. No extraction, recursive cleanup or pre-existing content read.

The strict UTF-8 JSON envelope has exactly version=AP-PH/1, pr_number, parent,
descriptor (canonical base64) and objects (ordered records with exactly oid/data,
canonical base64). Duplicate keys anywhere, extra fields, invalid encoding,
truncation or excess size refuse. The descriptor is the unchanged CP-03 schema:
canonical numeric repository/Issue IDs and name, scope, base, feature ref,
expected old SHA, exact new HEAD/tree and complete file inventory. The envelope
parent must match the separately pinned expected old SHA. Its SHA-256 must equal
the trusted policy's artifact_sha256; a digest is correlation, never approval.
There is no serialized policy or authority loader. Policy/Request repr is redacted;
Result encodes only fixed codes, counts and non-authorizing safety constants.

All CP-03 limits and restrictions remain: <=16 KiB descriptor, <=256 KiB/object,
<=1 MiB descriptor plus canonical objects, <=130 objects, <=128 flat ASCII paths,
ordinary files or explicitly authorized executable paths, one canonical parent.
The 1 MiB encoded-wire cap is an additional stricter ceiling, not an increase of
any existing cap. Shared blobs are allowed; duplicate/unreachable objects, unsafe
paths/case aliases, symlinks, submodules, nested trees, signed/merge/multiline
commits and real repository complexity beyond that profile **BLOCK**. No rewrite,
flattening, splitting, dropping signatures or regenerated commit is a fallback.
The current Agent Platform repository and ordinary real commits are not silently
representable in this deliberately narrow fixture profile.

CP-03 `verify` still returns BLOCKED/remote_update_unverified for structurally
valid update bytes. AP-PH/1 uses only that specific final refusal, reached after
all existing content checks, as the input to a separate synthetic remote model.
It never converts it into CP-03 success or a production update receipt. CP-05's
create-only API and existing callers are unchanged.

## Exact existing-Draft fixture transaction

Only `update_fixture` invokes injected **trusted synthetic fixture ports**.
Ordinary byte parsing, construction and report encoding have no I/O. The fixed
port offers observe, create_object, read_object and compare_exchange, without
arbitrary method/endpoint/body, credentials or callable command arguments.
There is no create-PR, PR-body update, Ready, COMMENT/review, APPROVE, Issue close,
merge, force, delete, tag, settings or main mutation operation.

The separately trusted policy binds publication identities, scope, exact encoded
artifact, existing PR number, unchanged title and sole `Closes #N` body, expiry
<=300 seconds and one-use authenticated human authorization reference. Frozen
objects and fabricated admission flags do not authenticate a human. The trusted
admission must independently bind every intended effect, fencing/revocation and
prior published history. Admission is refreshed before each observation and again
after durable intent confirmation, before dispatch. No generic live port is
supplied or admitted; `live_readiness()` is unconditionally BLOCKED.

An externally owned journal session must stay exclusive through the entire
attempt, including readback, crashes and failed result confirmation. Its claim
must join prior publication lineage and stable repo+Issue, repo+ref and repo+PR
guards across App/installation/authorization/namespace rotation. Claims, successes
and UNKNOWN cannot be evicted/reset to permit a new attempt. Legitimate future
updates need a separately admitted continuity transition from retained history;
this library implements no journal provisioning, release, reset or recovery.
A failed/uncertain claim already requires reconciliation even with zero writes.

Before every write, complete independent observations bind canonical repository,
selected installation/account, exact App/bot attribution and minimal CP-05 grants,
no events, open Issue/scope, current main, existing feature tip and exactly one
same-repo open Draft PR with sole native Issue association. Title/body/author and
all SHA/ref pins must match. Synthetic evidence additionally asserts publisher
isolation, App merge denial and atomic compare support; missing/unknown/false
facts stop even the fixture. These booleans are test assertions, not live proof.

Independently retrieved old-commit bytes prove an exact single-parent chain from
the expected old tip to the approved current base. At most 32 ancestors, each
<=256 KiB and <=1 MiB aggregate, are accepted; SHA-1/header/parent bytes are
recomputed. Missing, cyclic, reordered, merged, extra or incomplete ancestry
blocks. The validated new commit's sole parent is exactly that old tip. No
candidate-supplied `base_ancestor=true`, closed Issue or empty history proves it.

Objects are uploaded in blob/tree/commit dependency order. Each has its own
request-bound sequential UNKNOWN intent, exact readback and confirmed result.
All canonical objects are reread before the ref operation. The only final effect
is atomic compare_exchange(expected_old -> exact new commit) on the existing
feature branch; it must reject a different tip **and** non-fast-forward. No GET
then unconditional PATCH, force or presumed exclusivity against GitHub writers.
An intervening competing writer is rejected in the fixture even after a good GET.
Two independent complete post-effect observations and canonical-object readback
must confirm the unchanged Draft and exact new HEAD before terminal success.

Result UPDATED_OFFLINE_FIXTURE is a simulation, live_authorized=false. Any failure
after claim returns UNKNOWN_NEEDS_HUMAN, with confirmed count and retained intent;
no retry, automatic rollback/delete, blind duplicate send or assumed success.
BaseException propagates with history retained. Cooperative <=5-second per-call,
<=60-second operation/expiry checks stop late or reversed-clock effects. The
external adapter would need actual interruptible transport deadlines, <=64 KiB
ordinary responses and complete <=3 pages of 20. Python callbacks cannot prove
power-loss durability, independent rollback defense or interrupt blocked calls.

## CAS research record and unresolved live evidence

The official [GraphQL Git reference](https://docs.github.com/en/graphql/reference/git#updaterefs)
documents atomic batch application and a `beforeOid` precondition. `RefUpdate`
also contains `afterOid`, `force` and a fully qualified ref name; `UpdateRefsInput`
binds repositoryId and refUpdates. Zero OIDs represent absence/deletion, so a
existing-ref model refuses both; a future wire profile must also require one approved
feature ref and require force=false. These are documentation findings, not an
observed server transaction or an enabled request encoder.

The official [REST ref update reference](https://docs.github.com/en/rest/git/refs#update-a-reference)
documents sha/force, without an expected-old SHA parameter. Its fast-forward
check does not establish the exact-tip compare contract required here. This
library therefore supplies no GET-then-PATCH fallback.

Public documentation was retrieved without credentials on 2026-11-13. Exact
response byte sizes and SHA-256 hashes are pinned in the static requirements
record. They identify observed HTML, not an immutable GitHub schema, independent
audit or authorization. Legacy mutations/input-objects links redirected to the
reference index; the current Git-category source contains the relevant entries.
No authenticated schema introspection, GraphQL POST, permission probe or live
write was performed. official_schema_sha256 remains null and live
semantics_verified/permissions_verified remain false.

Real CAS mapping remains **BLOCKED** pending reviewed wire encoding, target/App
permission and server-side merge-denial evidence, concurrent/failed-request
behavior and the independent isolation/admission/continuity gates. Synthetic
compare_exchange is a fixture primitive only. clientMutationId is not assumed
to provide idempotency. Source-page hashes cannot enable a production adapter.

## Proposed operator bootstrap and future live gates

Before a first trusted publisher exists, a **separate narrowly authorized human
bootstrap** can transfer an inert exact local commit/patch from the worker to a
trusted management workstation. The human independently verifies source identity,
full commit and parent/tree/blob hashes, scoped diff, toolchain/test evidence and
absence of hooks/config execution, then explicitly decides whether to publish
that exact branch and Draft. No worker credential or automatic App publication is
required. This proposal is not an executable command/runbook or authorization to
push #103/#104, broaden checkout access or install a publisher.

A live pilot is another Issue and needs verified cross-principal confinement,
credential/signing custody, durable anchored replay history and reconciliation,
authenticated immutable human admission, actual per-worker App identity and
selected-repository grants, exact candidate format adequacy, verified official
CAS semantics and complete independent remote observations. Effective server-side
**App merge prohibition** remains mandatory: required checks/no ruleset bypass
and zero required approvals do not by themselves prove human-only merge. Broad
Contents/PR write can exceed this interface; a local allowlist cannot repair that.
If the server-side restriction cannot be established, live remains NO-GO.

No App permission changes, PEM/JWT/token/PAT, auth stores, credential helper,
SSH agent, production Codex, host/Proxmox/root, AppArmor/systemd activation or
remote writes occur in PUB-01. Offline tests are not independent host attestation,
security review or current GitHub governance evidence. Delivery is one local
commit, no push/PR, for subsequent separate AP-SM/2 technical review.
