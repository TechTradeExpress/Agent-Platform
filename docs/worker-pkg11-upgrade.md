# PKG-11: uniquely identified -8 source and historical -7 upgrade evidence (#152)

SOURCE_ONLY / INSTALL_INERT / NO_LIVE / LIVE_NO_GO / HOST_NOT_RUN.
Exactly two role packages: `agent-platform-control`, `agent-platform-worker`.
No release, host install, service start, credential provisioning or Publisher
activation follows. Gate #73 and #108 remain BLOCKED; native/subscription/public
legacy execution stays SUBSCRIPTION_ISOLATION_BLOCKED / exit 13. One explicitly
selected harness per worker, auth/Publisher/Signer separation and human-only merge
are unchanged. HAR modules remain SOURCE_ONLY, excluded by role closure tests.
Neither Codex CLI nor Claude Code is bundled, acquired or run by package scripts.

## Current revision and immutable source contract

The builder now defaults to `0.1.0-8~git<FULL_SOURCE_SHA>` for both roles.
It requires a full 40-hex commit, a clean checkout of the same recipe and exports
the immutable Git tree. Source/tree/epoch, consumed-input hashes, installed manifest,
archive size/SHA-256 and actual tool versions remain bound in provenance.
Candidates sort above final -7 and below final -8; hash suffix ordering is not a
chronological upgrade policy. Same source/epoch/toolchain must rebuild byte-for-byte.
A different source commit produces a different candidate version, even if its tree
is identical. The code/dependency boundaries, accounts and state format do not change.

```sh
SOURCE_SHA=<full-reviewed-40-hex-source-commit>
python3 packaging/build_deb.py --source-commit "$SOURCE_SHA" --output /tmp/pkg11-candidate
```

`--ci-final-fixture` produces exact `0.1.0-8` solely for compatibility testing:
`build_kind=ci-final-fixture`, `ci_only=true`, `release_authorized=false` and
CANDIDATE / NOT_RELEASED. Ordinary candidates have ci_only=false, but still
release_authorized=false. This is not a release workflow. `--final-version` is
blocked: a separate post-merge release Issue must review final source/toolchain,
archive hashes, distribution and migration/host authority. No saved CI fixture or
computed digest can authorize release/install. `--synthetic-fixture --revision
3|4|5|6` retains the existing offline N/N+1 regression profiles, not historical
installed artifacts. Current code refuses revision 7 even at the low-level API.

The explicit historical map identifies -7 with immutable merged PKG-09 source
`0fbc940ae94144f8cc29c9a0fd98afc704f58168`, never current source relabelled -7.
Old -5/-6 and -7 doctor records retain their existing interpretation. New -8
records require exact commit-qualified candidate binding or explicit CI fixture
provenance, a full tree and release_authorized=false. Doctor remains read-only,
bounded, no-launch and blocked. No receipt migration or journal reset is added.

## PKG-10 audit and historical baseline

[PKG-10 #143](https://github.com/TechTradeExpress/Agent-Platform/issues/143) records
artifact preparation and an operator-reported worker01 -7 install. This task did
not access that host, its private state or the original archives. The source pins
are independently checked against local immutable Git objects:

| Identity | Pin |
| --- | --- |
| Commit | `0fbc940ae94144f8cc29c9a0fd98afc704f58168` |
| Tree | `222a6fc4925e10cf2891ae8c47034a72fc58a994` |
| Commit epoch | `1794855509` |
| Original recipe SHA-256 | `c17ef3b4c9b969b7ee0615e32b2773f20099a837d3b1aa45d99b237fcd329d78` |
| Reported Control archive | `ede90003c59151f1713e8888387065f9e9f5a9f9c902332c04fd2f9e4af7bb50` |
| Reported Worker archive | `91784281d9f9d438bcd48ee10dab45b73ab9bc1d93d44301efef7305cddbbfe0` |
| Reported installed Worker manifest | `9174f8ee35499b76d9b9f781d64826029c22cd802e3223015a32e53040afcfa9` |

References: [independent artifact review](https://github.com/TechTradeExpress/Agent-Platform/issues/143#issuecomment-6927206193),
[operator install report](https://github.com/TechTradeExpress/Agent-Platform/issues/143#issuecomment-6928307181).
The review reported identical package bytes on Debian 13 with Python 3.13.5,
dpkg-deb 1.22.22 and xz 5.8.1. Control's manifest pin is additionally reconstructed
from that immutable source; it is not an installed Control observation on worker01.

`packaging/debian/pkg11-baseline.json` and its code-pinned digest close this
historical mapping. `build_pkg11_baseline.py` verifies tree, epoch and recipe
**before** loading only that original builder. It exports the complete historical
tree, builds both -7 roles with the original recipe and exact tree/epoch, then
verifies both reported archive digests, manifests, embedded provenance and all
payload file hashes/modes/UID/GIDs. Only then is baseline-verification.json saved.
Missing objects, altered pins/recipe/manifests/archives or incompatible toolchains
are BLOCKED: no fallback, re-pinning, fetch, package repair or substitution with a
synthetic current-source artifact. Partial outputs are retained for inspection;
never retry into an uncertain pre-existing directory.

```sh
python3 packaging/debian/build_pkg11_baseline.py --output /tmp/pkg11-historical-7
```

Result: RECONSTRUCTED_MATCHES_REPORTED_HASHES, installed_artifact_verified=false,
original_archive_access=NOT_RUN. A fixture remains a reconstruction even if its
hash matches the report. Actual current worker01 archive/state/continuity and
installation are UNKNOWN / HOST_NOT_RUN in this task. Earlier operator authorization
and the no-backup exception in #143 do not authorize a new -8 deployment or prove
rollback/recovery. Do not label a generated package as the actual installed file.

## Disposable Debian 13 CI

The pinned Debian image, signed but mutable dependency acquisition, actual tool
inventory, existing P0 N/N+1, P1, lintian/autopkgtest and historical -6 to -7 cases
remain. Current source no longer emits a -7 compatibility package: both historical
upgrade steps consume the original-recipe historical-7 directory. Normal -8
candidates are rebuilt and compared separately from the exact -8 CI_ONLY fixture.
Build runs are unprivileged, network-none and read-only source. Installation runs
only as container-root in bounded, fresh disposable fixtures, without production
mounts, credentials, network, Docker socket or privileged-container flags.

Two fresh -7 to -8 containers independently test empty and fabricated UNKNOWN
journals; either failure or missing report fails CI. The existing disposable
worker-upgrade image reserves publisher UID:GID 999:989 and signer 995:987 before
dependencies, denies dependency service starts and guards Debian 13/testbed identity.
The lifecycle verifies historical archive/manifest identity before old tools
explicitly initialize only fresh synthetic P1 stores, then tests:

- APT co-install with preconfigured dependencies, then real dpkg unpack/configure;
- interruption boundaries with Control N+1 / Worker N, Worker unpacked, and Control
  configured / Worker unconfigured; read-only doctor blocks partial installation;
- exact receipt/journal bytes, inode/owner/mode, numeric account identities and
  named ACL retention across each cut and explicit completion;
- preserved administrator package.conf edits with doctor BLOCKED; the fixture then
  resets only its own synthetic edit to the exact new default for independent
  payload/state checks; retained AppArmor conffiles and static oneshot units;
- exact new provenance/manifests, no Codex/Claude or service activation, ordinary
  APT downgrade refusal without force, corrupt receipt STOP without regeneration.

This is controlled interruption at package-state boundaries, not power-loss,
crash-consistency or verified rollback proof. Profile bytes/parser results do not
prove kernel attachment; container files do not prove a live systemd manager.
Effective systemd/AppArmor/BPF, namespace/auth/tool isolation, hosted execution in
this local task and real worker deployment remain NOT_RUN. Missing disposable
runtimes/tools mean NOT_RUN, never host installation or privileged fallback.

## Later operator migration / backup / rollback / STOP plan — no authority here

A separate post-merge release task must pin the actual final -8 source/tree,
recipe/toolchain and both artifact hashes, confirm compatible receipt/state
semantics and define final distribution. Each host needs its own explicit human
approval naming exact files/digests and allowed commands. No approval transfers
from a PR candidate, CI PASS, worker01's old -7 install or another worker.

Before proposing any transaction, the operator independently inventories installed
-7 artifact/source/manifest, dpkg state, current UID/GID/groups, ACLs, conffiles,
unit/drop-in/reload/profile metadata, receipt and retained continuity evidence.
Do not expose journals, credentials, login stores or signer material. Missing or
drifting identity, active units, UNKNOWN effects or absent continuity is STOP.
The operator must explicitly resolve backup/recovery policy and retain protected
backups/anchors without disclosing them to coding tools. The old no-backup
exception is a historical unproven-recovery risk, not a satisfied backup gate.
This task neither creates backups nor requests host access.

After a separately authorized transaction, the operator must independently check
configured package/provenance/manifest, unchanged IDs/ACL/journals/receipt and
conffiles/units, with all runtime gates still blocked. Stop on edited conffile
prompts, partial state, unexpected defaults, receipt mismatch or side effects;
retain evidence. Explicit completion of an interrupted package configure requires
human reconciliation first. Never force downgrade, re-label current bytes as -7,
regenerate receipts, erase UNKNOWN, auto-retry effects or infer safe rollback from
a package version. Any restore requires reviewed continuity and separate approval.
No services, daemon reload, kernel profiles, tool downloads or Publisher pilot
are authorized by the package upgrade plan.
