# Disposable Linux native-canary fixture — Issue #28

Specification **AP-NCF/1**, 2026-11-02. This is a guarded build/audit **recipe and
review plan**, not an installer, a VM definition accepted for deployment, or
permission to execute it. No provisioning or kernel run was performed by this PR.
The existing [canary contract](native-canary.md) and
[architecture decision](architecture-trust-boundaries.md) remain binding.

## Evidence and provenance

The operator supplied [comment 6589316861](https://github.com/TechTradeExpress/Agent-Platform/issues/28#issuecomment-6589316861).
Its complete JSON block is preserved in
[sandbox01-report.json](fixtures/native-canary-v1/sandbox01-report.json).
[Provenance](fixtures/native-canary-v1/sandbox01-provenance.json) records the remote
comment identity/timestamps and SHA-256 of the comment body and extracted JSON
file. These are snapshot correlation hashes, not signatures or independent
confirmation of the guest, operator identity, permission or execution history.
The raw guest report and audit logs were not delivered to this repository.

| Operator-reported measurement | Result |
| --- | --- |
| Source | `0179c665fd8053b3a4978477a6304bf6d49fef78` |
| Environment | Disposable Proxmox VM 101 `sandbox01`; Debian 13 Trixie; Linux `6.12.113+deb13-amd64`; x86_64; 2 vCPU, 3072 MiB, 30 GiB |
| Network | No VM NIC, only guest loopback; no homelab connection |
| Caller / invocation | Unprivileged `canary`; system Python and pinned source, `native_canary.main(["--run-synthetic"])`, no installed CLI entry point |
| Evidence | `REAL_KERNEL_SYNTHETIC`, operator-reported remote snapshot |
| Host containment / worker CODEX_HOME | PASS / PASS |
| Same-domain CODEX_HOME | FAIL: deliberately read-only-mounted synthetic credential was readable |
| Overall | BLOCKED, exit 13, `same_domain_credential_exposure` |
| Namespaces, caps, files, worktree, proc, FDs, network, IPC, descendants | All confinement booleans true in both modes; `home_readable` false for worker, true for same-domain |
| Authentication / internal Codex routes | AUTH_E2E_NOT_RUN / UNKNOWN |
| Artifact admission | BLOCKED: 308,139,304 bytes exceeds unchanged 268,435,456-byte cap |

The current repository probe SHA-256 independently matches the reported
`c6f7321d1e5a00a0b9e0e46ba36c3437f9f739dde43bee0a9aba0dbdc59aec2d`.
That verifies source correlation only, not which bytes actually ran in the VM.
The runtime manifest SHA is reported as
`37aa74083d1755f7563bcdd7b1e2b4ccab49054743956bdedcfddda1e802a295`;
its bytes/inventory were not supplied, so that hash has not been recomputed.
Reported inventory: **293 files, 319 entries, 15,356,345 regular-file bytes**.
Being under limits does not establish that individual files or ELF closure passed
an independent audit. The operator reports those audits passed; this PR does not
repeat or independently attest them.

A VM around an entire CLI can protect the host while tools in the same credential
domain still read CODEX_HOME. This synthetic same-domain FAIL is the expected
negative demonstration, not safe native authentication or built-in tool mediation.
Stock subscription-funded Codex remains selected; native execute/subscription
remain SUBSCRIPTION_ISOLATION_BLOCKED / exit 13, and public run/resume/doctor remain
quarantined. No API fallback, account access, writer or runtime promotion follows.

## Reproduction status and input lock

[fixture-plan.json](fixtures/native-canary-v1/fixture-plan.json) separates reported
pins from **required missing inputs**. Its authority flags are all false and its
status is `BLOCKED_MISSING_INPUTS`. Nulls must not be filled with guessed hashes,
current host packages or a newly downloaded unpinned version.

Known reported supply-chain pins:

- Bootstrap ISO `sandbox01-bootstrap-draft-v0.2.iso`:
  `c9e3ed974b0c7051b2850b44c6f27046e9afb5192aff383b97d54f0dd0112c2a`.
- Debian Bubblewrap `0.12.0-1~deb13u1` package:
  `70aca4fa8daeacb677ec00e8063eb586f08ae3d94b1f11e684370b5524c43431`.
- Installed `/usr/bin/bwrap`:
  `573236e5328ac2ebb08f59ae3a9805b4f8d12bdef14be8af4450d5463294985f`.

The experiment's build/audit scripts are **outside the repository and have not
been supplied or reviewed here**. Neither ISO nor package bytes, signed Debian
indexes, complete package lock, source archive hash, Python version/closure,
raw runtime manifest nor build logs are present. They are not verified repository
artifacts. Debian version/architecture and a package hash alone are not a complete
reproducible build specification. Byte-identical reproduction of sandbox01 is
therefore **not yet verified**, and cannot honestly be promised from this bundle.

To lift the reproduction blocker, the operator must deliver these nonsecret
inputs through normal review, with origin, digest, size and license for every
artifact; source archive hash must match the exact archived commit. Include
original scripts as inert review inputs first, including all commands, environment
and package/path selection. Do not execute code merely because its hash is in a
comment or because it is on an ISO. Independently inspect it for downloads,
auth/home copying, broad mounts, privilege changes and hidden fallbacks.

## Deterministic build procedure (proposal; not executed)

Every stage has a stop condition. The following algorithm is a concrete target
for the delivered scripts and independent review, **not a claim that the old
scripts implemented it**. An incomplete lock means stop before building. A build
requires separate human authorization for a new disposable VM; this Issue handoff
does not authorize it, and dev01 is never the target.

1. Freeze an input bundle: base Debian install media identity/hash; signed
   InRelease/Release, Packages indexes and trusted Debian key fingerprints; every
   `.deb` name/version/architecture/size/SHA-256; source archive and exact commit;
   reviewed script revisions; Python executable/stdlib/extension selection and
   exact import allowlist. Verify the signature chain against separately trusted
   keys and hash each package against the signed index. Confirm Bubblewrap's
   package and extracted binary against the pins above. Stop on unknown origin,
   revoked/unavailable verification, extra input, mismatch or incomplete closure.
   A checksum file shipped alongside untrusted bytes is not provenance.
2. Define a fresh offline disposable VM matching the recorded hardware/OS/kernel
   target, no NIC, no host shares, passthrough, clipboard, agents with host authority
   or credential media. Review the hypervisor manifest separately. Only fixed
   offline bootstrap media may be attached. Record the actual kernel and package
   versions; matching an OS label is insufficient. No host namespace/sysctl,
   capability, ownership, service or network repair is allowed by this recipe.
3. In that separately authorized VM, stage a new empty build directory and set
   locale `C`, timezone UTC, umask 022, fixed SOURCE_DATE_EPOCH derived from the
   pinned commit and an explicit executable PATH. Use no inherited user Python
   path/site packages. Do not merge with, overwrite or repair an existing runtime.
   List package archives before extraction; reject traversal, absolute names,
   devices, unsafe links and duplicate destination conflicts. Extract only reviewed
   package payloads to staging, without running package maintainer scripts.
4. Select the package-owned Python executable and the smallest explicit module/
   extension set needed by `_native_canary_probe.py` and its bounded subprocess
   probes. Record each selected path's package, source member, digest, destination
   and selection reason. Do not copy `/usr/lib`, a host virtualenv, `/etc`, homes,
   Codex, keys or a recursively discovered host library tree. No glob-based
   dependency copying. Every selected file must come from the verified bundle.
5. Derive ELF closure **statically**, without running candidates or `ldd`: record
   ELF class/machine, PT_INTERP, DT_NEEDED and any RPATH/RUNPATH for the interpreter
   and each extension/shared library. Use a reviewed finite loader-path policy;
   resolve each SONAME to one pinned package member. Reject missing/ambiguous,
   unused, escaping or unsupported dependencies and unexpected loader paths.
   Record recursive dependency edges and resolved hashes. Do not reuse the native
   Codex artifact as the Python fixture or relax any native/legacy admission cap.
6. Materialize selected aliases as independent regular files from the verified
   target member, recording the mapping; never copy a symlink blindly. Reject
   cycles, escaping aliases, hardlinks (including internal ones), special files,
   setuid/setgid/sticky bits and security.capability xattrs. Explicit directory
   modes 0755, executable files 0555, data files 0444; logical UID/GID 0 in the
   artifact. These are proposed deterministic build modes, not recovered metadata
   of sandbox01. Normalize recorded mtimes to SOURCE_DATE_EPOCH and reject any
   metadata not covered by the normalization policy. No chown/install on dev01.
7. Rootfs contains only reviewed `bin`, `usr`, `lib`, `lib64` files plus empty
   `proc`, `dev`, `workspace`, `codex-home` directories and zero-byte regular
   `canary-probe.py`, `canary-policy.json`. No hidden files, credential names,
   `home`, `root`, `run`, sockets or populated mountpoints. Sort paths by UTF-8
   byte order; require unique portable relative names, no `..` or absolute paths.
   Read each regular file once with no-follow/open/fstat checks and bounded
   hashing; compare identity/size/mtime/ctime after the read. Any race aborts.
8. Emit manifest **exactly** `{version: 1, bwrap_sha256: HASH, files: {PATH: HASH}}`.
   Deterministic proposed serialization: UTF-8, sorted keys, compact separators,
   no NaN/duplicate keys, one final newline. Separate sidecar records file sizes,
   modes, logical ownership, package mappings, ELF edges, source/probe/script pins
   and normalized environment. Manifest <=65,536 bytes, <=512 regular files,
   <=2,048 entries and <=67,108,864 file bytes; bwrap <=2,097,152 bytes. Empty
   placeholders are included in the file map. Hash the exact manifest bytes;
   semantic JSON equality does not reproduce its hash. The original manifest
   serialization is unknown; do not assume this recipe yields the reported SHA.
9. Build twice into independent fresh staging trees from the same locked inputs.
   Compare sorted inventories, hashes, sizes, modes, ownership mappings, ELF
   closure and manifest bytes. Optional deterministic archives use sorted names,
   fixed numeric UID/GID/mtime, no variable PAX metadata and compression timestamps
   disabled. Compare archives separately from the installed-file inventory.
   Differences stop review; do not silently update the expected hashes. A fresh
   reproducible build may legitimately have a different digest from sandbox01;
   treat it as a new candidate requiring review, never relabel the old experiment.

## Audit and staged rollout (proposal; separate consent required)

Before any installation, an independent reviewer compares inputs, scripts, static
closure and two-build results. No script may grant itself approval. Only after
separate explicit human permission in the disposable VM may the approved artifact
be installed at `/opt/agent-platform/native-canary-v1` and trusted bwrap at
`/usr/bin/bwrap`, root-owned and not writable by the tester. Rootfs is not merged
with existing contents. Installation must preserve the reviewed no-link inventory,
reject nested/bind mounts and record actual ownership, modes and capability xattrs.
Compare exact installed file and manifest/bwrap digests against the reviewed build.
The canary's `native_canary._runtime`, `_trusted`, `isolation.trusted` and
`isolation.check_worktree` remain the final existing read-only admission checks,
not a replacement for static package/ELF provenance review.

On the separately approved fixture only, record Linux architecture, UID/GID,
`/proc/self/status` CapEff/CapPrm/CapInh/CapAmb all zero, namespace support/policy,
no inherited privileged FD/socket, no NIC and no external mount. Inventory FDs
without reading sensitive content. Zero capabilities and private modes are
prerequisites, not the trust boundary by themselves. Missing namespaces or policy
means BLOCKED; no sysctl/setcap/setuid/root fallback. Validate namespace/cgroup
availability through the existing mandatory canary paths only on explicit opt-in.

A bounded allowlisted Python import/loader smoke test would execute the reviewed
fixture interpreter and therefore needs its own operator permission; static ELF
success does not establish that imports work. It must run isolated, no host
library fallback/site packages, no network/credentials; record the exact imports,
command, timeout, output limit and result. Its original script/log is missing.

A later kernel invocation is a further separately authorized action, not a build
step or a CI test. Reuse the existing fixed `_arguments`: mandatory user/IPC/PID/
net/UTS/cgroup namespaces (mount namespace checked inside), read-only curated
rootfs/private proc/dev, cleared environment, cap drop, no sensitive inherited
FDs, zero capabilities and NoNewPrivs=1 verified inside both views, only synthetic
worktree writes, fixture-owned sentinel proc/TCP/Unix socket
negative checks and bounded child reaping. Only the same-domain view receives a
read-only bind of fabricated CODEX_HOME. No custom dispatch, broader mounts,
optional namespace flags or alternate commands. Capture stdout JSON and exit
status separately, hashes, exact source/kernel/runtime/bwrap identities and
nonsecret audit logs; preserve original bytes and document any export/redaction.
The prior invocation is recorded above and **is not repeated by this PR**.

Rollback is stop/quarantine and preserve evidence. Never automatically delete
unknown paths, reap unrelated processes, rerun an uncertain operation, repair a
runtime or change host security to obtain PASS. An operator may separately approve
disposal of the whole verified VM after evidence export; never apply cleanup to
host paths or shared storage. Retaining sandbox01 is an operator decision.

## Offline repository verification and remaining gates

`uv run pytest tests/test_native_fixture.py` validates the saved evidence's schema,
source-probe correlation, unchanged caps and negative verdicts; it also exercises
existing runtime audit code on inert synthetic files with explicitly mocked
administrative ownership/capability observations. It executes no Bubblewrap,
fixture interpreter, VM, kernel canary, credential or model. New adversarial
checks reject unsafe extra content, aliases, missing/changed manifest and resource
limits without modifying the existing host-prerequisite test. Normal full CI
retains its skipped real-kernel opt-in; green CI is **VERIFIED_OFFLINE only**.

Recorded kernel observations are an **operator-reported remote snapshot**, not a
new independently verified kernel run. Reproduction inputs/script audit and
byte-identical build remain BLOCKED; real authentication NOT_RUN; complete native
tool mediation UNKNOWN. #51's independent GO/NO-GO, artifact admission and any
credential-bearing integration remain separate gates. No Issue closure, merge,
production readiness, scheduler, publisher or host provisioning is implied.
