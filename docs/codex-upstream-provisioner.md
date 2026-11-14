# PKG-03R: verified upstream Codex provisioning

Source-only implementation of Issue #116 under ADR 007 / AP-PKG/2. The tool is
`provisioning/codex_upstream.py`; it is **not** in either Debian P0 package or the
Python wheel. P0 Worker still rejects `codex install`; run/resume/doctor and
native execution retain their existing refusals. No installer runs from dpkg,
maintainer scripts, package upgrade/purge, service, Codex tool or scheduler.
No Codex executable is distributed in this repository or its generated artifacts.

## Reviewed release policy and provenance

The controlled `provisioning/codex-release-lock.json` selects **0.166.0**,
`rust-v0.166.0`, official release ID 428320524, asset ID 689712643, target
`x86_64-unknown-linux-musl`. This is a new pin-selection investigation, not an
admission inherited from #110. Fresh public upstream release metadata was read;
its archive digest matches freshly rehashed cached archive bytes. The new parser
also freshly verified the archive and its extracted ELF, without installing or
executing it. The archive is 121764138 bytes; the executable is 319346888 bytes.
Exact hashes, URL, sizes, platform and structural ABI contract are in the lock.
The version is bound by the reviewed exact content identity and signed release
workflow ref, not by executing an untrusted `--version` or trusting tar filenames.

Authentication evidence goes beyond an observed HTTPS checksum: the official
binary's `.sigstore` bundle verified with **Cosign v3.1.4**, exact certificate
identity
`https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/rust-v0.166.0`
and issuer `https://token.actions.githubusercontent.com`. Certificate chain and
transparency-log verification were enabled; result **Verified OK / exit 0**.
The binary was only read as data. The archive's official API digest binds the
container; extraction binds its sole executable to that signed binary digest.

The public bundle, trusted-root snapshot and small provenance report are in
`provisioning/evidence/`. The verifier tool's fixed URL/size/SHA-256, public API
response hash, signature identity and verification limits are recorded there.
No private key, token or vendor executable is included. The signature verification
used a fresh isolated HOME and normal Sigstore TUF trust initialization, not any
operator login store. See the primary [Cosign verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/).

A reviewer can independently verify existing official bytes with the pinned
Cosign version and committed public bundle, using the exact identity/issuer
above. The basic command is:

```text
cosign verify-blob --bundle codex-0.166.0.sigstore \
  --certificate-identity https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/rust-v0.166.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com codex-official-binary
```

The provisioner itself is stdlib-only and downloads no verifier, CA update or
signature dependency. Its compiled release-lock SHA-256 binds all accepted pins;
it also verifies the pinned provenance-file bytes. Root-owned code, policy and
ancestors are mandatory. There is no `--lock`, alternative endpoint, latest,
unverified input, environment override or runtime synthetic-policy flag. A future
release needs a reviewed code/lock/evidence update, retaining unchanged pins for
all managed versions that may still exist. Checksums do not independently prove
authorship; Sigstore roots, verifier/bootstrap supply chain, official HTTPS and
source review remain trust inputs. Signature verification does not establish
reproducible source-to-binary equivalence, a full component inventory or runtime
admission. This installer does not reopen #110's superseded redistribution work.

## Source interface and #111 integration

Only an operator can invoke this one-shot tool. It requires root, Debian 13
amd64, a root-owned nonwritable code/policy tree and explicit `--approve`.
An agentdev checkout cannot serve as a privileged policy installation. The
self-check is defense in depth, not a privilege boundary against already
executed untrusted Python; the administrator must deploy reviewed immutable code
before invocation. Never run sudo on a Codex-writable checkout.

The source interface (after independently authorized root-owned deployment) is:

```text
python3 -IB /trusted/code/provisioning/codex_upstream.py install \
  --version 0.166.0 --approve --operator-path /usr/local/bin:/usr/bin:/bin
python3 -IB /trusted/code/provisioning/codex_upstream.py install \
  --version 0.166.0 --archive /operator/supplied/pinned.tar.gz \
  --approve --operator-path /usr/local/bin:/usr/bin:/bin
```

A different higher reviewed version additionally requires `--upgrade`. Explicit
`rollback --version <retained-older-version>` never downloads or invents a pin.
`recover` accepts no version/archive/upgrade and requires the same explicit
approval and operator PATH. Its outcome is described below. No command executes
the candidate, even for version checking; no auth stores or shell files are read.

#111 must introduce the operator-only `agent-platform-worker codex install`
dispatch, plus explicit upgrade/rollback/recover handling, in a separately
reviewed phase. It must copy only this reviewed code/lock/evidence closure to a
root-owned private location with appropriate isolated `python3 -IB` dispatch,
extend the role manifest deliberately, verify package provenance and enforce an
operator boundary. P0 is unchanged. No setuid/sudo helper, privileged service or
IPC bridge from Codex is supplied here. #112 independently diagnoses installed
records/hash/ABI/PATH; installation success is never subscription or publishing
permission. Source availability alone authorizes no real host deployment.

## Download and validation

The only initial origin/path is the lock's exact official GitHub asset URL;
bytes remain bound to the immutable hash if a tag/asset URL changes. At most two
HTTPS redirects may lead to `release-assets.githubusercontent.com` under its
fixed release-asset prefix. Userinfo, non-443 ports, control characters, other
hosts/paths, HTTP/file URLs and fragments refuse. DNS/CA are trusted OS inputs;
this is not independent network isolation or an IP-pinning claim.

The client uses an explicit verified TLS context and Debian CA bundle, TLS >=1.2,
without proxy/netrc/custom-CA/keylog environment discovery. GET only, no credentials,
no automatic retries. Exact Content-Length and identity encoding are required;
transfer-encoding ambiguity refuses. A main-thread timer bounds the whole network
operation including headers/redirects to 120 seconds; reads, sizes and redirects
are bounded. Public CDN query strings and transport exceptions are never logged.
Offline input uses nofollow, nonblocking regular singly-linked file inspection,
exact size/hash and stable metadata before/after reading. Both paths share the
same archive/binary verifier and activation transaction.

Validation stays in memory before any persistent write. Archive <=160 MiB,
executable <=384 MiB; standalone CLI caps address space at 2 GiB, CPU at 180 seconds
and per-file writes at 384 MiB without raising existing limits. Extraction has
its own 60-second timer. The restricted tar reader accepts exactly one ordinary
0755 member with the pinned name/size, normal padding and bounded zero trailer;
it never invokes filesystem extraction. Links, directories, devices, traversal,
extended/PAX/GNU headers, extra entries, set-ID/writable modes, CRC/truncation and
expanded trailing data refuse. Archive ownership/attributes are never copied.
ELF64 little-endian amd64 executable/load headers are inspected; PT_INTERP,
DT_NEEDED/RPATH/RUNPATH/TEXTREL refuse. Static-musl provenance is the upstream target
plus structural ELF closure, not a full CPU/security or execution-readiness proof.
The 384 MiB provisioning ceiling does not alter native runtime's 256 MiB gate.

## Filesystem transaction and recovery

Managed root: `/opt/agent-platform-codex`, root:root 0755. Its exact inventory is
`store.json`, `versions/`, `current` and, only while an operation is pending,
`transaction.json` and `.current.next`. Each retained version is
`versions/<version>-<full-binary-sha256>/{codex,record.json}`. Binary 0755, JSON
0644; directories 0755. Records bind exact release-pin digest, archive identity,
executable digest/size and version. No accounts, credentials, services or mutable
per-user configuration belong here.

All fixed ancestors are opened without following links and held by directory FDs.
Root ownership, safe modes, file link count, inode/metadata stability, device,
ACL/default ACL and file-capability checks protect managed paths. Existing trusted
parent and command directories are flocked nonblockingly throughout an operation;
no lock file is created during validation. Foreign/unsafe state or contention
refuses. This assumes a trusted host/root administrator, not isolation from root
compromise, filesystem rollback, or uncooperative privileged mutation.

`/usr/bin/codex` must be absent; it is never adopted or overwritten. The conventional
`/usr/local/bin/codex` must be vacant on first install or the exact previously
managed root-owned link to `/opt/agent-platform-codex/current/codex`. Its parents
must already exist safely. Unknown files, links and temporaries refuse. Explicit
operator PATH is checked by lstat only; earlier Codex entries or absent managed
command selection refuse. No HOME discovery, executable lookup/launch, profile
rewrite or reading of `~/.codex` occurs. User `~/.local/bin/codex` is preserved.
PATH is only an observation at that instant: aliases/shell caches/later edits
remain operator/#112 concerns. Trusted callers use the returned absolute versioned
path, never PATH as authority.

After complete input/state validation, create an exclusive durable intent,
stage/fsync the binary and record in a private 0700 directory, change that
completed directory to 0755, rename the completed version, and fsync.
Create the conventional link only when vacant, then atomically replace the
`current` symlink. The executable and record are selected together by that one
pointer; old versions remain intact. Only a verified completed intent is removed.
There is no automatic pruning: at most three reviewed retained versions are
allowed; exceeding the bound requires separate operator maintenance review.
No automatic downgrade, same-version rebinding, deleting unknown state or
unverified rollback is supported. Idempotence revalidates installed bytes and
records before returning without writes or downloading.

| Interruption | Explicit outcome |
| --- | --- |
| Validation/network/archive failure | No managed store/link/config writes; fixed refusal |
| Root creation, intent or partial/complete `.stage` retained before version publication | BLOCKED; retain every byte for scoped administrator reconciliation, no implicit retry/cleanup |
| Fully published verified version with exact durable intent, old/new current and known link/pointer state | Explicit `recover --approve` revalidates all bytes/pins and completes only that transaction |
| New current committed but intent remains | Explicit recover confirms the same version and completes durable bookkeeping |
| Noncanonical/changed intent, unknown file/version, modified record/binary, missing historical pin or conflicting link | BLOCKED without repair; preserve data |

Normal install never silently recovers. A recovery request cannot select another
version. Rollback atomically selects only an intact already reviewed retained
version; it never rolls back or touches journals/checkpoints/user data. These
fsync/rename boundaries and injected-failure tests are not power-loss, reboot,
production-host or independent anti-rollback evidence.

## Validation scope

Unit tests use small fake ELF/tar bytes and controlled HTTP fixtures with an
explicit injected test connector; production CLI has no plaintext transport or
synthetic-pin option. Separate Debian tests run in an approved disposable Debian
13 amd64 user/mount/PID/network namespace, no external network, no host homes or
Docker socket. They exercise real fixed paths, UID/GID 0 ownership, offline/fake
HTTP install, idempotence, upgrade, rollback, recovery and preservation of fabricated
user tool/auth sentinels. They never install or execute the official binary.
The fixed-root helper refuses ordinary host root using its explicit fixture marker
and one-UID non-host-root namespace mapping. It is test code, not a provisioner.

Real workers/control/Proxmox, official on-host installation, Codex execution/login,
service boot, deployment and GitHub mutation remain NOT_RUN. LIVE_NO_GO, Gate #73,
SUBSCRIPTION_ISOLATION_BLOCKED and existing exit-13 barriers remain unchanged.

## This iteration's observed checks

Base `af645368008302048fce6172fadd4d861dcdc31b`; public main/fetched origin/main
and merged PR #118 verified. Fresh upstream tag/object GETs also confirmed source
`6ff1e1ca3b30fc8b914720681fcf5fe62e95f856`. Dedicated feature worktree; LOCAL_ONLY.

- Ruff: PASS. Provisioner + existing P0 package tests: **104 passed**.
- Disposable pinned Debian 13 amd64: **70 passed**, plus explicit fixed-root
  offline/HTTP/idempotence/upgrade/rollback/recover and user-data proof: PASS.
  Network was private, dependencies pre-cached, no real accounts/credentials,
  vendor binary, host home or Docker socket exposed. Source mounted read-only.
- Fresh official archive/ELF validation: PASS as data only. Sigstore exact
  identity/issuer, certificate chain and transparency verification: exit 0.
- Full pytest: **3240 passed, 2 failed, 1 skipped**. Both failures reproduced
  independently on an isolated unchanged-parent snapshot:
  `test_file_mutation_after_digest_read_is_detected` (`invalid_load` vs
  `file_changed`) and
  `test_changing_evidence_before_write_is_blocked[journal]` (`read_only` vs
  `needs_human`). Their code/tests were not changed or skipped. Full PASS is not
  claimed.
- `git diff --check`: PASS. P0 manifests, package code, runtime gates and wheel
  entrypoints unchanged. GitHub CI is NOT_RUN for local-only delivery.

The fixture used the existing pinned official Debian image
`sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d`.
A new private copy reused verified image/cache inputs. Only test dependencies were
added to that copy; signed APT indexes remain mutable, not a hermetic snapshot.
The single-UID namespace used root as APT's testbed sandbox user; the enforced
outer namespaces and disabled lifecycle network remained intact. No host security
configuration or privilege mapping was provisioned. Native execution, login,
physical worker installation, reboot/power-loss proof and #111/#112 integration
remain NOT_RUN, not implied by synthetic PASS.
