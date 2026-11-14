# PKG-03 fourth pass: large isolated fixture tested, pinned lock rejected

2026-11-14. Local parent `848463c9909c89d698313ec57def781b4668cf20`.
The existing `/tmp/agent-platform-issue-110` worktree/common Git directory,
feature branch, exact HEAD and clean tracked/untracked state were verified.
No reset, rebase, remote mutation, host configuration, service, credentials or
runtime activation. **Cargo was not retried on the old small filesystem.**

**Result: BLOCKED remains; no .deb.** Adequate writable storage was found and
the bounded job actually ran. The previous storage obstacle was removed; the
new failure is **CARGO_LOCKED_UPDATE_REQUIRED**, not another disk-full outcome.

## Available environment and resource design

Read-only capacity discovery found the old `/tmp` filesystem at about 3.1 GB
total. A separate filesystem under the authorized repository root had
**105467994112 bytes total / 96063090688 bytes free**. A new owner-only fixture
was created under an already ignored scratch path on that larger filesystem.
No existing checkout file, ignored data, branch or worktree was overwritten.
After completion it was retained under ignored `build/` scratch rather than
leaving a non-venv directory at `.venv`; only this task's new empty staging
parent was removed. The new cache is retained for reconciliation; no unrelated
storage was cleaned.

[resolution-job-inputs.json](../packaging/codex/resolution-job-inputs.json)
pins the complete source-tree observation and all **147 assembled toolchain
entries**. Every assembled entry was checked against the exact official Rust
1.95.0 component archives/digests before the run. Codex source remains
`6ff1e1ca3b30fc8b914720681fcf5fe62e95f856`; all original manifests, Cargo.lock,
workspace membership and `.cargo` configuration remain unchanged.

[resolution_job.py](../packaging/codex/resolution_job.py) is an explicitly
invoked developer-only job, **not an Agent Platform runtime launcher or service**.
Without `--execute` it returns NOT_RUN/exit 13 without source inspection/network.
The flag records local execution intent; it does not supply authority outside
the human's task. The package builder does not include/wire this helper.

| Resource | Fixed job policy |
| --- | --- |
| Filesystem admission | At least 80 GiB total and 64 GiB available; refuse before Cargo/network on a small FS |
| Cache/free space | Monitor 32 GiB cache ceiling and 16 GiB free reserve; never evict/reset caches to obtain success |
| Time | 900 seconds for the complete metadata + tree sequence, sampled every two seconds |
| Memory | Hard per-process address-space ceiling 4 GiB; monitored supervised-tree RSS stop at 2 GiB |
| Other process limits | Per-process CPU 900 seconds, individual file size 4 GiB, 1024 file descriptors |
| Output | 64 MiB combined stdout/stderr per command; retain failure output, never treat partial JSON as success |
| Network | Explicit host allowlist, HTTPS CONNECT port 443 only; public IPv4 destinations, no private/loopback destinations through proxy; at most 512 tunnels and 16 GiB relayed TLS payload |
| Retry | `CARGO_NET_RETRY=0`; no automatic job retry or fallback source version |

Disk/RSS/wall-clock/output guards are monitored limits and may overshoot between
samples. Address space, file size, FD and CPU limits are inherited hard prlimits.
RSS is not an atomic cgroup memory ceiling. Network accounting covers relayed
TLS payload, not link-layer retransmissions/DNS or TCP/header overhead. No
independent production-isolation or universal reproducibility claim follows.

The transient loopback proxy accepts only CONNECT, rejects auth headers, pins
allowed destinations and resolves only globally routable addresses. Cargo and
Git are explicitly configured to use it; Git permits HTTPS only, no SSH/file
transport or credential helper. TLS is still verified end-to-end by Cargo/Git
against the fixed guest system CA path. The job shares the host network namespace
for this proxy path; this is a **trusted-tool acquisition budget**, not proof of
kernel-enforced egress confinement against arbitrary hostile code. No upstream
build scripts or repository code run. The proxy is not installed or persisted.

Bubblewrap uses private user/PID/IPC/etc. namespaces, empty HOME/CARGO_HOME,
read-only source/toolchain, private temporary/proc/device views, dropped caps and
closed inherited FDs. Host user homes and credential stores are not mounted.
Cargo/Git source acquisition is the sole authorized network operation. Owned-job
cancellation uses pidfd; failure never signals an unrelated PID or resets state.
System Git/bwrap/CA/util-linux remain guest prerequisites, not an independently
attested immutable OS image; the full toolchain/source pins do not prove that
additional supply-chain boundary.

## Observed run, not a proposed PASS

[large-fixture-observation.json](../packaging/codex/large-fixture-observation.json)
contains exact executed-recipe/input hashes, telemetry, redacted diagnostic
hashes, command/result and before/after input verification. Original executed
recipe bytes and raw outputs are retained in the private fixture, not emitted
as public logs. Final helper changes add stricter inventory/private-directory/
pidfd preflight checks; those were tested offline and rechecked against the
same actual inputs, **not used to claim a second online resolution success**.

The job's fixed sequence was:

```text
cargo metadata --locked --format-version 1 --filter-platform x86_64-unknown-linux-musl
cargo tree --locked --target x86_64-unknown-linux-musl -p codex-cli -e normal,features
```

Only the first command ran; the second was correctly NOT_RUN after failure.
`CARGO_NET_GIT_FETCH_WITH_CLI=true` matches the inspected upstream release
transport setting. This is not a change to manifest features or selected roots.

Observed metadata result:

- Exit **101**, no supervisor/resource stop, **0 stdout bytes**.
- Cargo specifically refused to update Cargo.lock because `--locked` prevents
  the update. No alternative lock was generated or accepted.
- About **196 seconds**, **2666883448 relayed TLS bytes**, **31 tunnels**,
  about **6.21 GB logical cache**, peak sampled RSS **1025286144 bytes**.
- Minimum sampled free space **92267192320 bytes**; the storage and other
  configured budgets were not exhausted.
- All pinned source/toolchain bytes verified again after exit. Cargo.lock
  remains SHA-256 `22bd51f50864ce40f6686f3350c0547fdd50a8213240f54435ed394f68bf08e6`.

One additional **offline** diagnostic used `metadata --frozen` (locked + offline)
against that cache, with bounded time/output and resolver diagnostics. It also
returned **101 / zero metadata** and the same lock-update refusal. Raw diagnostic
text is not published; its size/hash and result are retained. No network refetch,
unlock, manifest rewrite or lock regeneration was performed for this diagnostic.

This establishes that the checked source/lock + Cargo 1.95.0 combination is
rejected by the locked resolver in this observed environment. It does **not**
identify which lock changes Cargo would propose or prove a universal upstream
defect. The earlier release workflow inspection found no `--locked` flag on the
multibinary release build, so a checked-in lock cannot automatically be asserted
to be the effective release lock. No new graph is inferred from resolver logs
or partial downloaded sources, and V8/ICU workspace fetches remain distinct from
CLI binary membership.

## What is now needed

The missing evidence is no longer access to a large disk. It is an authoritative
explanation/artifact for the rejected **exact pinned lock/input combination**:

1. Upstream can supply the effective Cargo.lock and target/features/native input
   report from the official 0.166.0 release, with provenance and hashes. Any
   difference from the checked-in lock requires explicit review of the source/
   artifact contract; do not silently replace this task's immutable input.
2. Alternatively, the operator may separately scope a diagnostic on a disposable
   copy that records proposed lock differences without promoting the result to
   a release graph. That is **not authorized/performed by this job**: this task
   requires the existing Cargo.lock unchanged. A derived successful resolution
   would not alone prove what went into the official executable.
3. If upstream explains how the exact original inputs resolve without alteration,
   validate that explanation in a new explicit job. Repeated downloads or more
   disk alone do not remedy the observed lock refusal.

Removing `--locked`, omitting the V8 workspace, patching manifests, selecting a
new Cargo version or reusing a provisional graph as successful evidence would
violate the current scope. No such fallback is implemented.

## Concrete one-shot CI/disposable-VM handoff

The larger environment was available here, so no infrastructure was provisioned.
For an independently repeated observation **after the input conflict is resolved**,
use an approved disposable Debian 13 amd64 guest with at least 128 GiB scratch
storage, 8 GiB RAM and four CPUs. Provide pre-reviewed Python >=3.12, Git,
bubblewrap, util-linux/prlimit and CA certificates in a pinned guest image; record
its digest and exact package versions. No workers/control01/pve01 changes, host
container socket, real homes, keys, login caches or privileged fallback.

Transfer the exact reviewed helper/pin files, source-tree observation, verified
source and Rust tools as read-only inputs. Independently verify their hashes.
Create a **new** private job root with empty 0700 `cargo`, `home`, `output` dirs
on the large scratch filesystem. Invoke once:

```sh
python3 -I packaging/codex/resolution_job.py \
  --source /inputs/source --tools /inputs/tools --tree /inputs/tree.json \
  --fixture /scratch/new-job --execute
```

Use the same fixed limits/allowlist. A CI/VM supervisor should additionally impose
a hard aggregate memory ceiling and disk quota; the local helper's sampled
guards are not substitutes for those kernel limits. No scheduler, automatic
retry, daemon, upload credential or enabled GitHub workflow is introduced here.
Retain job result/telemetry, exact command/versions, lock hashes before/after,
full stdout artifacts and bounded private diagnostics; publish only redacted
results/digests. Partial/uncertain output remains BLOCKED for reconciliation.

On successful command exits, validate complete metadata JSON/resolve nodes and
actual CLI tree/root/features before calling resolution observed. Account for
workspace feature unification, target predicates, build vs normal edges and
native/resource inputs. Cargo resolution is still **not** official-binary link
provenance, a complete license/NOTICE inventory or MPL compliance. Reconcile those
separately with the existing source candidate bundle. No state/receipt/JSON flag,
CI green or this job's result can clear LIVE_NO_GO or authorize a .deb release.

## Gate outcomes

| Gate | Result after this run |
| --- | --- |
| Actual target CLI graph | **BLOCKED_PINNED_LOCK_REJECTED_BY_CARGO**; no metadata or CLI tree |
| Complete license/copyright/NOTICE manifest | **BLOCKED**; no complete selected component set to validate |
| MPL delivery | Existing **11 verified source candidates / PARTIAL**, not the complete binary MPL set |
| Package/runtime | No .deb, no package lifecycle claim, no runtime activation; **LIVE_NO_GO** |

## Local validation

Ruff PASS; **128 focused tests passed**, including 18 new cases for resource/
network policy, source inventory, pidfd preflight, explicit invocation and report
integrity. Actual final-recipe input preflight revalidated the complete source/
toolchain without another Cargo invocation. Documentation links and
`git diff --check` passed.

Full pytest: **3225 passed, 2 failed, 1 skipped**. Both failures reproduced on an
isolated snapshot of exact unchanged parent
`848463c9909c89d698313ec57def781b4668cf20`:
`test_file_mutation_after_digest_read_is_detected` and
`test_changing_evidence_before_write_is_blocked[journal]`. Their implementations
are unchanged; no skip or security weakening was added. This is not full-suite
PASS. The official-asset preflight remains BLOCKED; package build/lifecycle and
complete license clearance remain NOT_RUN/BLOCKED, not synthetic success.
