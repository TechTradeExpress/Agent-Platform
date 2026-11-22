# PUB-05 offline reconciliation for worker01

Scope is the worker01 homelab-supervised create attempt for Issue #169 with
exactly one unresolved blob effect followed by confirmed token revocation.
Production journals, job, credential paths and unit state are frozen.
This is a source-only validator. There is no command, collector, recovery writer,
package deployment, or exception to Publisher or Signer admission.

## State and trust

`inspect` returns `STOP` or `HISTORY_VERIFIED` for the supplied offline snapshot.
The latter validates the history shape and its binding to the job and candidate.
It does not resolve the original effect. `preview` additionally validates
pinned independent evidence, an exact new candidate and an explicit
operator decision. Success is `PREVIEW_ONLY`. Both APIs always deny admission
and publication. A failure returns only a fixed category. No raw input, key,
JWT, token, raw GitHub response or job ID is emitted.

Root and the Proxmox administrator are trusted. External rollback protection is
NOT_PROVIDED. The caller supplies expected snapshot, evidence and decision
digests from trusted custody separately from the records. Hashes correlate
bytes. They cannot authenticate a person, establish independent observation,
or prove persistence. The caller must obtain evidence from an independently
authorized read-only observer and keep the operator decision under root custody.
The validator has no remote, credential or host interfaces.

## Exact preview prerequisites

- The original AP-WP/1 job and artifact validate and match the independently
  pinned snapshot digest. The original job is expired. Both raw journals are
  canonical and linked from the empty digest; their raw hashes and chain tips
  are bound to the snapshot. Their exact records match the v4 failure profile.
  The UNKNOWN digest binds the approved raw Git blob ID, and the blob is in the
  original candidate. Mint and revoke confirmation markers must match.
- Evidence is bound to that snapshot and both proposed input hashes. The
  required facts carry per-fact time, source, result and visibility. The fixed
  results are observed, absent and unknown. Unknown or limited evidence blocks.
  Absence is bounded to observation time and a complete authorized visibility
  scope. Observations must be after expiration of the original job and at most
  five minutes old. Future observations block.
- An independent observer must authenticate repository identity, protected
  current main, the open Issue, exact App installation account, allowed grants
  and main bypass policy. Use authorized read-only credentials separate from
  the worker App, with access to the entire relevant inventory. Exact old and
  proposed refs, all-state PRs for both refs, native linked PRs for the Issue,
  original tree and commit are checked independently. Unavailable visibility,
  paging, incomplete scope or conflicting reads mean unknown. Compare the
  observed blob's canonical bytes with the approved candidate. An accessible
  blob cannot determine how or when it was created.
- A separate host observer must confirm the frozen snapshot digest, exact retained
  allowlist, idle units and retained output by metadata, with JWT expiry bounded by the exact original
  job. Inspect no JWT bytes. Confirmed revoke records a successful reply and
  its journal append for the known token. It cannot prove the original object
  effect, erase retained credentials, or establish the current remote state.
  Missing token disposition or uncertain revocation blocks this profile.
- The proposed homelab job needs the same repository, worker, App and Issue
  identities, a different ID, head, feature ref and artifact, exact fresh main
  as direct parent and an independent review bound to its job and artifact
  hashes. Both journal pins must refer to the frozen original journals. A
  distinct protected main observation is required; historical parent support
  is outside scope. The operator decision binds both cases and the exact
  evidence and has a five-minute maximum lifetime. Approval is for offline
  preview only.

## Separate durability and admission design required

Production resolution would require a separate, canonical create-only decision
store with root ownership, private permissions, descriptor validation without
symlinks or hardlinks, existing non-creating locks, same-descriptor verification,
bounded reads and fsync of file and directory. It must use a stable namespace
for the original job and refuse duplicate resolution. It must require an
independently held continuity pin, including evidence of the exact committed
decision. A receipt alone cannot prove persistence across a failed fsync,
partial write, interrupted process or administrator rollback.

The proposed host state progression is frozen UNKNOWN, durable resolution
intent, independently confirmed resolution, then separately authorized new-job
admission. A missing, duplicate, changed, partially written or uncertain
record stops. Never repair or retry an uncertain boundary. Production admission
needs a separately reviewed lifecycle holding the original locks through
revalidation, any host transitions, fresh approval, and consumption of the
new job intent. It must preserve the original record bytes and permanently
deny the old ID and ref as well as collisions or unrelated unresolved
history. A consumed decision or stale evidence cannot admit another job.
Check both journal bytes and chain heads, current host artifact and retained
unit state, fresh trusted observations and exact new job immediately before
any effects. Require a fresh Signer result and new token under the existing
custody and confinement rules, and preserve human-only merge. Missing root or
independent authorization stops.

The eventual retirement of retained credentials, case archiving and cleanup
of the runtime egress allowlist each require separate authorization and
recorded evidence. Do not change the frozen host for this issue. These
durability and production admission transitions are **NO-GO** pending separate
design, implementation, review, package and host authorization.

For offline fixture intake, `read_snapshot` accepts a dedicated, prevalidated
directory descriptor and takes a nonblocking exclusive lock on that directory.
The caller must verify the directory and every ancestor before handing over
the descriptor. It reads only `job.json`, `candidate.json`, `publisher.jsonl`
and `signer.jsonl` from that private root-owned fixture directory and checks
file identity and metadata through stable rereads. Original live journal
owners and modes are outside this offline envelope. A busy lock, unsafe
metadata, changed file or missing input refuses without creating anything.
The resulting bytes still require the independent snapshot pin.

## PUB-06 case custody and continuity

The Worker P1 operator adds a root-only `reconcile-v4` subcommand with
`inspect`, `preview`, `record` and `confirm`. It is pinned to worker01 #169
v4, the original object and both exact journal hashes. It uses the existing
configuration lock and read-only locks on both original journals, checks
the failed and quiescent unit states and retained JWT metadata, and copies
only job, candidate and journal bytes. The JWT is never opened.

After separate host authorization, root must arrange a private existing
`/var/lib/ap-publisher-recovery` directory owned by root with mode 0700.
No package hook creates or migrates this directory. Stage root-owned
0600 singly linked inputs `proposed-job.json`, `proposed-candidate.json`,
`evidence.json` and `decision.json` satisfying PUB-05. Obtain the three
pins from separately trusted custody. Inspect requires `--snapshot-sha256`. Preview and record also need
`--evidence-sha256` and `--decision-sha256`. These inputs validate exact
bytes, and custody must independently authenticate the sources.

Inspect and preview are read-only. Record requires explicit
`--authorize-record`. It exclusively creates a fixed intent, the archived
bytes and a final record under lock, with file and directory fsync. A failed
or interrupted record requires manual review of the entire directory.
Do not reconstruct missing markers or repeat an uncertain record. Retain
the returned continuity digest separately only after a successful record.
Read-only confirm takes only the independently retained
`--continuity-sha256`. Under the case-directory lock it checks the final
marker, canonical intent, exact archived file set and contents. On success it
reports `CUSTODY_CONFIRMED` with `remote_effects_unresolved`. Confirmation
works after approval expiry or restart, including when temporary inputs and
retained runtime metadata are no longer available. It reads no live job,
journal, JWT or unit state. Inspect, preview and record keep their original
checks, including approval freshness where applicable. A digest computed from a surviving file after an uncertain
write cannot substitute for the separately retained pin.

This confirmation covers local case custody only. The evidence format and
hash checks cannot authenticate the GitHub observer or establish whether
its privileges cover main restrictions and native closing-link inventory.
The next stage requires an independently authenticated observation mechanism
or a trusted signed evidence contract with provisioned observer identity and
completeness checks. The production admission path also needs a reviewed
atomic single-use transition under both role locks and fresh case-specific
revalidation. No consumer for the case record is installed in Signer or
Publisher. Existing job/JWT, journal and launch guards continue to refuse.
Do not retire evidence, start services or retry #169 on this basis.


### Remaining admission gates

1. Define an independently provisioned observer contract for this repository
   and App. Pin the observer principal and signing public key under root
   custody, separate from the worker App and publication credentials.
   Bind a fresh signed result to the exact worker case, proposed job,
   challenge, observation time and endpoint scope. Verify the actual read
   capabilities through authenticated successful observations of branch
   restrictions and bypass actors, the installed App's identity and grants,
   and complete exact-ref and native Issue-linked PR inventory. Each denied,
   truncated, incomplete or ambiguous observation must produce STOP. A valid
   signature alone cannot establish visibility.
2. With that contract reviewed, add a separate launch decision bound to the
   confirmed archive, fresh observation challenge, exact new job and a
   unique authorization ID. Under configuration and both role locks,
   recheck the old journal pins, current main and candidate. Write and
   durably confirm an exclusive consumption intent before anything can
   start, preserving the old attempt. Use an explicitly bound fresh journal
   generation if needed, available only to that exact new launch. Both
   roles must reject the old ref, old ID, foreign generation and any
   existing or uncertain claim. Preserve independent authorization for any
   retirement of retained state.
3. Test races, lost persistence acknowledgments, replay after restart,
   claim-before-mint interruption and authorization expiry. An interrupted
   consumption cannot renew approval or automatically start either role.
   Keep live deployment and the first #169 attempt separately authorized.
