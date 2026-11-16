# PKG-09: Worker P1 version and offline upgrade contract (#138)

SOURCE_ONLY / INSTALL_INERT / HOST_NOT_RUN / LIVE_NO_GO. No deployment or pilot
is authorized here. Exactly two project packages remain: Control and Worker.
No Codex or Claude executable/package/dependency is supplied. #108 and Gate #73
remain open/blocked; subscription/native/legacy execution stays exit 13.

## Collision diagnosis and version rules

The previous builder treated revisions -3/-4/-5/-6 as synthetic payload profiles,
not immutable releases. It defaulted to -6 for every source commit. Embedded
source/manifest provenance distinguished contents, but dpkg compares Version,
not that provenance. Thus installed worker01 `0.1.0-6` from `938c554...` and the
PKG-08 PR archive `0.1.0-6` from `c9781e40...` have the same version and different
contents. Never install one over the other or call them identical artifacts.

The next explicit revision is **0.1.0-7**, with identical Control behavior and
the same closed P1 inventories, accounts, paths and dependencies. Public builds
require a complete 40-hex source commit and a clean checkout of the same recipe.
The source is exported from Git, not read from mutable worktree files. Source
epoch, full commit/tree, consumed-input hashes, role manifests and external
archive size/hash/tool versions are recorded. No wall-clock versioning/latest,
Git-distance inference, dirty-source attestation or new parallel builder.

- Normal PR candidate: `0.1.0-7~git<FULL_SOURCE_SHA>`. Different source commits
  cannot silently reuse the same candidate version. This sorts above -6 and
  below final -7; hash suffixes do not define chronological candidate ordering.
- `--final-version`: explicit `0.1.0-7`, still **CANDIDATE / NOT_RELEASED** in
  provenance. This flag is not approval, signing, release or install authority.
- `--synthetic-fixture --revision 3|4|5|6`: old profiles for offline regression
  only. They are explicitly marked synthetic and are NOT historical packages.
  Ordinary invocations cannot accidentally generate a new deployable -6.
- Once a final -7 is accepted/installed, never rebuild different source as a
  replacement -7. A later change requires the next reviewed revision. There is
  no global release registry/signing authority in this offline builder.

Candidate rendering changes only the selected changelog header, version strings
and provenance deterministically; source changelog bytes are not edited. Exact
same inputs/epoch/toolchain must reproduce identical archives. The same version
is never sufficient identity: full archive, manifest and source hashes are
mandatory. Cross-toolchain equality is not assumed. Debian CI's pinned base
still uses signed but mutable APT indexes; record actual tool/dependency versions.

```sh
SOURCE_SHA=<full-reviewed-40-hex-source-commit>
python3 packaging/build_deb.py --source-commit "$SOURCE_SHA" --output /tmp/pkg09-candidate
```

## Actual historical baseline, not current source under -6

`packaging/debian/worker-baseline.json` pins:

- source `938c5543757c4184635e08330115527f0108064a`;
- tree `8aa3800cea7ba6a2ccdfc09852f487c42796ce22`, epoch `1794775064`;
- original recipe SHA-256
  `d2274f7221406cdc933ce031443ca798624d575f98bd640258d93e20ca180d06`;
- installed manifest SHA-256
  `80519eb56b98c4a5cd1ff222676dea2639c691f08fc318254d68b891d35152fa`.

The separate fixture preparation helper exports that immutable commit and runs
**its original recipe** at -6. It refuses recipe/tree/epoch/manifest drift and
writes baseline-verification.json only after validation. Its reconstructed
payload manifest was matched locally to the operator-reported installed one.
The operator's original archive hash is UNKNOWN. A reconstruction's recorded
archive hash is not claimed to be that unknown original hash. Missing Git
objects, unsupported toolchain or a different manifest is STOP, not permission
to re-pin expectations, fetch credentials or substitute the current builder.

```sh
python3 packaging/debian/build_worker_baseline.py --output /tmp/worker01-baseline
```

This requires local historical Git objects and a compatible build toolchain;
it performs no network/install and is not shipped as a host command.

## Disposable Debian CI and recovery

The additional worker-upgrade image reserves operator-reported publisher
999/989 and signer 995/987 **inside a disposable fixture**, before dependencies.
It does not provision or repair the real host. Its no-secret, network-none tests
install both baseline role packages and verify the exact historical manifest,
then explicitly initialize only new synthetic stores with the installed old tool.
Empty and synthetic UNKNOWN journal cases exercise:

- ordinary APT co-install with already configured distribution dependencies;
- real -6 to exact -7 dpkg unpack/configure and package-state interruption;
- exact numeric identities, directory/journal inode/owner/modes, named ACL and
  receipt retention, followed by explicit idempotent verification;
- root-owned new code and manifests; static oneshot definitions, no automatic
  publisher/signer/Codex activation; unchanged AppArmor conffiles;
- preserved administrator conffile edits with doctor BLOCKED, not repaired;
- ordinary APT downgrade refusal and retention of the newer installed version;
- corrupt receipt STOP without automatic regeneration or journal reset.

CI builds a clearly separated **pkg09-upgrade-test** exact -7 compatibility
fixture using --final-version. It is NOT a released post-merge artifact and must
never be used for host installation. Normal review artifacts live separately in
pkg09-candidate with the source-qualified version. Existing P0/P1 lifecycle,
prior bad-manpage negative, lintian, autopkgtest and separate synthetic Codex
installer/rollback cases remain. P0 smoke is unchanged; installed P1 has its own
read-only blocked smoke, instead of pretending a P1 package has no units.

Expected new doctor: package INSTALLED with exact manifest, state CONFIGURED
when receipt/resources match, status BLOCKED/exit13, bpf BLOCKED with no approved
egress, job_namespace and credential_handoff NOT_RUN, launch_allowed=false,
HOST_NOT_RUN and LIVE_NO_GO. Unconfigured dpkg status, malformed provenance,
manifest mismatch or missing/corrupt receipt must block. No receipt migration
is needed or silently performed. New version/tree/candidate binding is checked;
old -5/-6 provenance remains readable under its existing contract.

Default APT downgrade refusal is not universal anti-rollback enforcement: raw
`dpkg -i`, force options or manual state changes can bypass normal APT policy.
They are not approved recovery steps. No such forced downgrade is tested or
recommended. Interrupted configuration may be explicitly completed only after
package/state review. UNKNOWN remains reconciliation, not replay authority.
Kernel profile attachment, effective manager reload, running BPF and credentials
are NOT_RUN in this suite, not inferred from static files or parser success.

## Future worker01 operator plan — NOT authorization

Run only after a separate direct human approval naming host, exact package
file/SHA-256, scope, backups and STOP/rollback conditions. worker02 requires its
own approval. No command below is being executed on either worker here.

1. Record the old package version, full archive hash if available, embedded
   source commit and manifest digest using read-only inspection. It must match
   the baseline above; unknown/different version or source is STOP. Record current
   service IDs, exact ACLs, inactive/static units, drop-ins, daemon reload state,
   profile hashes, doctor JSON and independently retained continuity evidence.
   Never read auth stores, PEM/JWT/session contents or coding homes.
2. After merge, independently verify the accepted merged source SHA/tree, checkout
   the clean approved source, and rebuild using the reviewed toolchain:

   ```sh
   MERGED_SHA=<exact-approved-post-merge-40-hex-SHA>
   python3 packaging/build_deb.py --source-commit "$MERGED_SHA" --final-version --output /tmp/pkg09-postmerge
   sha256sum /tmp/pkg09-postmerge/*.deb
   dpkg-deb -f /tmp/pkg09-postmerge/agent-platform-worker_0.1.0-7_amd64.deb Package Version Architecture Depends
   ```

   Compare full hashes, external provenance, source/tree/epoch, embedded build.json
   and manifest SHA, exact payload/metadata and reproducibility before approval.
   Merge changes source commit, possibly tree and hashes. PR candidate or exact
   -7 CI fixture hashes do NOT transfer approval to the post-merge build. No
   signed release or verified distribution feed is implied.
3. Arrange administrator-owned backups of dpkg state, package archive, conffiles,
   identities and protected journals/receipts/anchors without exposing them to
   agentdev/Codex. Record access-controlled backup identity and continuity proof,
   not secret data, in the review report. Abort on active units or unknown effects.
4. Only the separately approved operator may propose the normal APT transaction
   for the exact local file, without force, same-version substitution or account
   repair. This document does not authorize executing it. Do not start/enable
   services, obtain credentials, fetch Codex, change BPF or alter personal tools.
5. Verify dpkg configured status/version, exact new provenance/manifest/code,
   unchanged IDs/ACLs/journals/receipt bytes, conffiles and no process activation.
   A changed vendor unit can require a separate approved manager daemon-reload;
   the package performs none. NeedDaemonReload or retained edited conffiles may
   leave units/package checks BLOCKED until human reconciliation. AppArmor loads
   and attachment are separate approved actions, never automatic readiness.
6. STOP on any missing evidence, source collision, changed state, conffile prompt,
   partial install, receipt mismatch or unexpected doctor result. Preserve logs
   and protected state. Do not regenerate receipts, erase UNKNOWN, retry external
   operations or force-install an old archive. Recovery/restore needs explicit
   approval and independently verified continuity, not a generic rollback command.

Operator report: exact host/approval reference; old/new file hashes, versions,
source/tree and manifests; dependency/tool versions; UID/GID and ACL metadata;
dpkg state; conffile/units/profile observations; preserved-state proof; doctor
checks including all NOT_RUN; uncertainty and STOP decision. No raw credentials,
private traces or assertion that CI equals worker01 evidence.

## PR #141 initial-install failure: APT local acquisition (#138 follow-up)

Reviewed failure: run `43909729542`, job `133448032430`, checkout
`da1fcd8c995216cf683b3c7ec8ca6295f35932a8`. PR remained open/Draft.
Package builds and the historical manifest check passed. Initial baseline APT
installation failed before the -7 upgrade; the old wrapper discarded its output.
The original CI stderr is therefore not recoverable from that job log.

A nonprivileged Debian APT 3.0.4 fixture reproduced the command-option failure:

```text
E: Internal Error, Pathname to install is not absolute 'ap-pkg09-acquire-one_1.0_amd64.deb'
```

The fixture has empty private APT state/config/sources/cache, two synthetic local
.debs with no scripts/dependencies, and a sentinel replacing dpkg. With
`--no-download`, APT stops with code 100 before the unpack sentinel. Without it,
APT resolves absolute local archive paths and reaches that sentinel, which
intentionally refuses unpack with code 99. Nothing is installed. This isolates
local acquisition from preinst, identities, ACLs and journals; none is relaxed.
It is not a reproduction of a complete Docker installation or worker01 state.

Offline is enforced by the existing Docker `--network none`, not by disabling
APT's local .deb acquisition. Remove --no-download from local archive transactions;
dependencies still must be preconfigured in the image. The downgrade negative
also requires the actual APT `--allow-downgrades` refusal message; an unrelated
nonzero acquisition error must not count as rollback protection.

On unexpected command status, the fixture now emits a bounded closed JSON record:
command/stage/returncode, output lengths, truncation indication and fixed public
APT/dpkg message classifications. Raw stdout/stderr, argv paths, environment and
unknown text are never echoed. Unrecognized output remains unclassified and
failed. Expected BLOCKED/exit13 output is returned unchanged to the test. English
locale and a fixed test PATH retain activation tripwires. Both fresh containers
(empty and UNKNOWN cases) run independently even if one fails; either failure
fails the CI step. No retry or state cleanup is introduced.

Local full apt/dpkg upgrade remains NOT_RUN: Docker/Podman unavailable. The
nonprivileged acquisition/downgrade tests use a dpkg sentinel and cannot prove
preinst or real install success. The next approved GitHub Actions run must pass
both complete cases before acceptance; prior lintian/autopkgtest success does
not establish this. No host, services, App credentials, permissions or BPF were
changed, and all runtime gates remain unchanged.
