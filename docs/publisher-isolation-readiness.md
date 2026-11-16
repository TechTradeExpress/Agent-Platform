# PKG-08 isolation and JWT handoff evidence (#128)

SOURCE_ONLY / OFFLINE_ONLY / HOST_NOT_RUN / LIVE_NO_GO. This is not deployment,
activation, credential access or publication approval. Gate #73 BLOCKED,
subscription/native/legacy exit 13 and human-only merge remain unchanged.

## Baseline and findings

Implementation base: `938c5543757c4184635e08330115527f0108064a`.
#122 is closed and PR #123 is merged (ancestor
`6669bfea985e004a2689515920604f99af892d8d`). Its sole approved job-bound
network drop-in, exact hash/expiry/peer checks and deny-default remain unchanged.
#108 remains open for separately approved worker01 then worker02 live pilots.

The Issue's worker01 observations are operator-reported history, not tests run
by this implementation. The exact combined host harness producing ERROR_None
is not in this repository: its exception origin cannot be established here.
A deterministic synthetic TimeoutError has errno=None. Formatting only errno
therefore loses the distinction between an expected timeout and other faults.
This is a demonstrated diagnostic ambiguity, not proof of the host root cause.

`packaging/worker-publisher/isolation_readiness.py` is a source-only injected
fixture primitive, not a packaged CLI, service runner or default network client.
`tcp_attempt` reports a closed stage/type/errno/outcome record; it never returns
exception messages, traces, paths, addresses or secret values. The caller must
bound the injected connect operation and fixture lifetime. `network_result`
requires a connected positive control with server receipt, denied attempt and
explicit absence of server receipt for timeout/EACCES/EPERM to mean temporary
probe PASS. Missing controls/receipt observation mean UNKNOWN. A refusal,
unreachable route, unexpected exception or successful deny connection remains
FAIL. It never equates a probe to configured policy or running BPF evidence:
`configured_policy=NOT_OBSERVED`, `production_bpf=NOT_RUN`, launch_allowed=false.
No broad allowlist, DNS inference, kernel manipulation or host retry is added.

## Exact staged-file contract

Only a separately authorized root administrator stages reviewed immutable bytes;
Codex/agentdev, Publisher and signer cannot stage or modify these resources.
The package installs code and templates, **not** operational job/candidate data.
Directory traversal ACLs alone never grant file read permission. The historical
runbook's commented file-ACL suggestions were insufficient as a mandatory step.

| Object | Owner/mode | Exact ACL in addition to root owner/group entries |
| --- | --- | --- |
| `/etc/ap-publisher` | root:root 0750 | named publisher and signer UID r-x; mask r-x; other --- |
| `job.json`, `receipts.json` | root:root 0440, regular, single link | named publisher and signer UID r--; mask r--; other --- |
| `candidate.json` | root:root 0440, regular, single link | named publisher UID r-- only; mask r--; other --- |

The group entry is root's r-x/r-- respectively; no supplementary shared group,
other named UID/GID, default ACL, writable mask, symlink, hardlink, capability or
NFS4 ACL is allowed. Use actual independently checked UIDs, not assumed IDs.
Do not blanket chmod/chown resources or reuse a coding checkout. Directory/file
ACLs must be staged and verified together, without a window exposing data.
No private home or real credential data is needed for this verification.

Doctor adds `job_access`: root metadata, type, links, exact modes, ACL readers
and stable file identity, without reading job/receipt/candidate contents. Missing
staging blocks this check; observation denied is NOT_RUN. Metadata success means
CONFIGURED only. `job_namespace` remains NOT_RUN: host-side ACLs do not prove the
unit's mount namespace, AppArmor or process can actually open the same inodes.
The two units' ReadOnlyPaths exposes the root-staged directory read-only; it
neither adds DAC permissions nor replaces identity/namespace probes. Actual
in-unit synthetic file-open and opposite-role denial require an independently
approved inert transient fixture. No such service was run here.

## One-shot signer and credential handoff

The exact namespaces are mandatory, including the CREDENTIALS_DIRECTORY value:

- signer: `/run/credentials/ap-worker-publisher-signer.service/app-key`;
- publisher: `/run/credentials/ap-worker-publisher.service/app-jwt`.

Missing, alternate, relative, cross-unit or normalized-alias directories block.
Only the signer can read its managed key copy; root/systemd, not Publisher,
transfers the signer-owned 0400 output at `/run/ap-publisher-signer/app-jwt`.
The output includes the exact job digest. Publisher verifies it against freshly
validated root job bytes. JWT expiry is bounded by that job, strictly future and
at most 300 seconds when signing; expired jobs cannot be published. The existing
CLAIM/UNKNOWN/COMPLETE journals enforce one-shot/replay checks across restarts.
No token is logged or made an approval receipt. The API remains the verifier of
App authentication; local token presence proves neither identity nor authority.

Publisher's After=signer is **ordering only**, effective when both jobs are
explicitly submitted; it never starts signer, requires it, or proves success.
No Wants/Requires/Install, auto-restart, cleanup hook or activation is introduced.
RuntimeDirectoryPreserve=yes is necessary for sequential signer-exit then
Publisher credential intake. Changing it to automatic removal at signer exit
would destroy the handoff. It also means physical bytes can outlive JWT validity;
expiry is a usability bound, not automatic file deletion or revocation proof.

| Event | Required outcome |
| --- | --- |
| Clean signer and successful handoff | Exclusive 0400 output, job-bound JWT, COMPLETE signing; root/systemd copies into Publisher-only mount; independent Publisher journal controls use |
| Wrong credential namespace or retained output | BLOCKED before a new signer claim/key read; retained symlink counts as retained output |
| Missing/unreadable key after UNKNOWN | BLOCKED; retain journal uncertainty; no automatic retry |
| Interruption during output write/fsync or before COMPLETE | Output may be partial/full, journal UNKNOWN; preserve both, block replay/restart |
| Same completed job restarted | Existing journal refuses replay; output cannot be overwritten |
| Expired job, stale runtime dir or previous output | STOP; never delete/reinitialize automatically or infer safe replay from absence |
| Publisher failure after an external attempt | Preserve existing UNKNOWN semantics; no re-sign/retry based on a lost result |

After separately approved execution, an administrator must reconcile both
journals, remote effects and credential lifetime before explicitly removing
only a positively identified consumed output. Do not reset journals or use a
fresh job/App rotation to bypass UNKNOWN. No automatic cleanup is supplied:
this Issue cannot establish token revocation or safe replay. Credential copies
have systemd unit lifetimes; actual root transfer, runtime ownership/mounts,
service teardown and crash/reboot behavior remain untested here. Doctor records
`credential_handoff=NOT_RUN`, not success inferred from unit files.

## Bounded operator-only future procedure

This checklist is not permission to run it. Each host and each inert transient
service requires a separate operator decision. Do not use production unit names,
real PEM/JWT/tokens, App operations, GitHub/OpenAI requests or coding homes.

1. Read-only preflight: approved package/source SHA and manifest hashes; actual
   public UID/GID and ACL metadata; inactive/static units; exact vendor fragments,
   no unexpected drop-ins or manager reload drift; read-only doctor JSON. Bound
   the command to 20 seconds, output to 64 KiB and do not include raw job files,
   credential mounts, environment dumps or unfiltered stderr in the report.
2. Keep #122's static job-bound network approval separate. An inactive unit with
   no cgroup attachment cannot supply live BPF evidence. Do not install guessed
   peers or change the production drop-in to make the probe pass.
3. Only after explicit inert-probe approval, an administrator constructs separate
   disposable units/paths using fabricated bytes and reviewed matching isolation.
   Limit each to 15 seconds, 32 MiB, 4 tasks, no restart and no non-loopback egress.
   Keep positive-control listener bounded to 2 seconds and at most one receipt
   per challenge; separately record whether the deny challenge was received.
   Preserve exception stage/type/errno via the source primitive. Unexpected
   outcomes are FAIL/UNKNOWN, never ERROR_None interpreted automatically as PASS.
4. Independently test both role file opens (job/receipts), publisher-only candidate,
   opposite journals/key mount/home denial, and same inode identity within the
   effective mount namespace. Report booleans and opaque challenge IDs only.
5. With a fabricated non-JWT credential, test exact credential directory, root
   transfer, distinct UID ownership, successful copy then both unit teardown,
   missing/stale/symlink output, wrong namespace, start ordering, restart,
   interruption and retained-directory behavior. Never use signing keys. Synthetic
   transfer is not App authentication, revocation proof or production readiness.
6. Inspect actual running fixture cgroup attachment plus controlled effects only
   for that fixture. A temporary fixture BPF PASS does not prove the real
   Publisher's running cgroup has the correct job-bound policy. The latter remains
   NOT_RUN absent separately authorized running-unit evidence.
7. STOP on any unknown receipt, identity, ownership, ACL, profile attachment,
   namespace, journal, cleanup or BPF state. Reconcile before further work; never
   broaden policy, repair credentials, repeat UNKNOWN or erase evidence.

Expected report: fixed schema/version, source/package hashes, fixture-only
challenge, stage/type/errno, positive/negative receipt booleans (unknown explicit),
static network policy state, temporary probe state, production BPF NOT_RUN,
job-access metadata CONFIGURED/BLOCKED, namespace/handoff NOT_RUN until actually
observed, remaining blockers and launch_allowed=false. Do not export JWTs or
secret-bearing traces. worker02 requires its own approval and evidence; do not
copy worker01's reported observations into a PASS.
